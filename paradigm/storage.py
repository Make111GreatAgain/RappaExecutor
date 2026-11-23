import os
import posixpath
from contextlib import suppress
from enum import Enum,auto
from functools import lru_cache
from typing import List
from urllib.parse import quote, unquote, urlsplit, urlunsplit
from uuid import uuid4

from pyarrow.fs import FileType, HadoopFileSystem

from config.config import BHExecutionNodeGlobalConfig
from paradigm.mod import ModelOutputType
from paradigm.replicate import ReplicateChunk
from utils.cryptography.commitment.commitment_computer import CommitmentComputer, CommitmentType
from utils.cryptography.commitment.kzg.kzg_commitment import KZGCommitment

"""
    NOTE: 这里是关于存储的部分
"""

# TODO: 这里目前是在内存里记录了所有的storedChunk并且它的路径是可以得到的，是否可以用数据库？不然节点down了怎么办


@lru_cache(maxsize=8)
def _hdfs_filesystem(endpoint):
    return HadoopFileSystem.from_uri(endpoint)


# 表示一个将被存储的文件块
# 需要记录的是: 1. 是哪个任务的第几个slot; 2. 是第几个chunk; 3. 存储的路径是什么
class StoredChunk:
    def __init__(
        self, storage_path, sign, slot, slot_hash, row_index, chunk_to_store: ReplicateChunk, *, use_hdfs=False
    ):
        # self.node_id = node_id #这个不重要
        self.sign = sign
        self.slot = slot
        self.row_index = row_index
        self.col_index = chunk_to_store.col_index
        self.slot_hash = slot_hash # Master为每个 CommitSlotItem赋予了slot_hash，这里记录，方便作为索引
        self.use_hdfs = use_hdfs
        self.store_path = self.generate_file_store_path(storage_path)

    def generate_file_store_path(self, storage_path):
        filename = f"{self.slot_hash}-row-{self.row_index}-{self.col_index}-chunk.slot"
        if self.use_hdfs:
            uri = urlsplit(os.fspath(storage_path))
            root = posixpath.normpath(unquote(uri.path))
            path = posixpath.normpath(posixpath.join(root, str(self.sign), str(self.slot), filename))
            if not path.startswith(root.rstrip("/") + "/"):
                raise OSError(f"HDFS chunk path is outside STORAGE_PATH: {path}")
            return urlunsplit((uri.scheme, uri.netloc, quote(path), uri.query, ""))

        file_dir = os.path.join(storage_path, str(self.sign), str(self.slot))
        os.makedirs(file_dir, exist_ok=True)
        return os.path.join(file_dir, filename)

    def _hdfs_location(self):
        uri = urlsplit(self.store_path)
        endpoint = urlunsplit((uri.scheme, uri.netloc, "/", uri.query, ""))
        return _hdfs_filesystem(endpoint), unquote(uri.path)

    def _existing_hdfs_chunk_matches(self, filesystem, path, data_bytes):
        info = filesystem.get_file_info(path)
        if info.type == FileType.NotFound:
            return False
        if info.type == FileType.File and info.size == len(data_bytes):
            with filesystem.open_input_file(path) as file:
                if file.read() == data_bytes:
                    return True
        raise FileExistsError(f"Chunk path already exists with different contents: {path}")

    def store(self, data_bytes):
        temporary_path = None
        try:
            if not self.use_hdfs:
                with open(self.store_path, "wb") as file:
                    file.write(data_bytes)
                return

            filesystem, path = self._hdfs_location()
            if self._existing_hdfs_chunk_matches(filesystem, path, data_bytes):
                return

            directory = posixpath.dirname(path)
            filesystem.create_dir(directory, recursive=True)
            temporary_path = posixpath.join(directory, f".{uuid4().hex}.tmp")
            with filesystem.open_output_stream(temporary_path) as file:
                file.write(data_bytes)
            if self._existing_hdfs_chunk_matches(filesystem, path, data_bytes):
                filesystem.delete_file(temporary_path)
            else:
                filesystem.move(temporary_path, path)
        except Exception as error:
            if temporary_path is not None:
                with suppress(OSError):
                    filesystem.delete_file(temporary_path)
            raise OSError(f"Failed to store chunk at {self.store_path}: {error}") from error

    def load(self):
        try:
            use_hdfs = getattr(self, "use_hdfs", None)
            if use_hdfs is None:
                use_hdfs = urlsplit(self.store_path).scheme == "hdfs"
            if use_hdfs:
                filesystem, path = self._hdfs_location()
                with filesystem.open_input_file(path) as file:
                    return file.read()
            with open(self.store_path, "rb") as file:
                return file.read()
        except Exception as e:
            raise OSError(f"Failed to load chunk at {self.store_path}: {e}") from e


"""
    NOTE: 这里是关于纠删码的部分
"""
class ErasureCodeRecoverError(Enum):
    INVALID_COMMITMENT = auto()
    NOT_MATCH_COMMITMENT = auto()
    TO_MANY_ERASURE = auto()
    # todo
    NONE = auto()

# ErasureCodeChunk 表示一个ec数据块，需要表示其index
class ErasureCodeChunk:
    def __init__(self, chunk, index):
        self.index = index
        self.chunk = chunk
# ErasureCodeChunks 就是所有的数据块，提供排序功能，并判断是否可恢复（KZG）
class ErasureCodeChunks:
    def __init__(self, padding_size=0, n=BHExecutionNodeGlobalConfig.EC_PARAMS_N, k=BHExecutionNodeGlobalConfig.EC_PARAMS_K, output_type=ModelOutputType.DATAFRAME):
        # TODO 这里需要加入文件类型如dataframe @YZM
        self.n = n
        self.k = k # 这两个参数暂时放在这里，考虑后面是否可以动态调整 todo
        self.padding_size = padding_size
        self.encoded_chunks: List[ErasureCodeChunk] = []
        self.kzg_commitment: KZGCommitment = KZGCommitment()# 这里设置KZG承诺 todo
        self.output_type = output_type
    def add_chunk(self, chunk: ErasureCodeChunk):
        self.encoded_chunks.append(chunk) # 这边就简单的插入即可
    def add_chunks(self, chunks: List[ErasureCodeChunk]):
        for chunk in chunks:
            self.add_chunk(chunk)
    def compute_kzg_commitment(self):
        # TODO 这里计算纠删码的KZG承诺 @YZM
        commitment_computer = CommitmentComputer()
        self.kzg_commitment = commitment_computer.compute_commitment([chunk.chunk for chunk in self.encoded_chunks], commitment_type=CommitmentType.KZG)
    def check(self) -> ErasureCodeRecoverError:
        # 在check之前一定要先去重
        if len(self.encoded_chunks) < self.k:
            return ErasureCodeRecoverError.TO_MANY_ERASURE
        # todo 这里需要check kzg承诺
        return ErasureCodeRecoverError.NONE
    def recover(self, decoder):
        # 将chunks按照index进行排序，并判断是否有重复
        # 使用字典来去重，同时保持插入顺序
        unique_chunks = list({chunk.index: chunk for chunk in self.encoded_chunks}.values())

        # 将去重后的chunks按照index进行排序
        self.encoded_chunks = sorted(unique_chunks, key=lambda x: x.index)
        error = self.check()
        if error != ErasureCodeRecoverError.NONE:
            return [], error
        # 传入decoder用于还原数据
        chunks, indices = zip(*[(item.chunk, item.index) for item in self.encoded_chunks[:self.k]])
        # print(chunks, indices)
        decoded_chunks = decoder.decode(chunks, indices) # decoder必须要实现decode todo 这样写不太严谨
        return decoded_chunks, ErasureCodeRecoverError.NONE
