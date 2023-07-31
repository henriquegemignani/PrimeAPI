#include <cstdio>
#include <cstdlib>
#include <cinttypes>
#include "nod/Util.hpp"
#include "nod/IFileIO.hpp"

namespace nod {

class FileIOFILE : public IFileIO {
  SystemString m_path;
  int64_t m_maxWriteSize;

public:
  FileIOFILE(SystemStringView path, int64_t maxWriteSize) : m_path(path), m_maxWriteSize(maxWriteSize) {}

  bool exists() {
    FILE* fp = Fopen(m_path.c_str(), _SYS_STR("rb"));
    if (!fp)
      return false;
    fclose(fp);
    return true;
  }

  uint64_t size() {
    FILE* fp = Fopen(m_path.c_str(), _SYS_STR("rb"));
    if (!fp)
      return 0;
    FSeek(fp, 0, SEEK_END);
    uint64_t result = FTell(fp);
    fclose(fp);
    return result;
  }

  struct WriteStream : public IFileIO::IWriteStream {
    FILE* fp;
    int64_t m_maxWriteSize;
    WriteStream(SystemStringView path, int64_t maxWriteSize, bool& err) : m_maxWriteSize(maxWriteSize) {
      fp = Fopen(path.data(), _SYS_STR("wb"));
      if (!fp) {
        LogModule.report(logvisor::Error, _SYS_STR("unable to open '%s' for writing"), path.data());
        err = true;
      }
    }
    WriteStream(SystemStringView path, uint64_t offset, int64_t maxWriteSize, bool& err)
    : m_maxWriteSize(maxWriteSize) {
      fp = Fopen(path.data(), _SYS_STR("ab"));
      if (!fp)
        goto FailLoc;
      fclose(fp);
      fp = Fopen(path.data(), _SYS_STR("r+b"));
      if (!fp)
        goto FailLoc;
      FSeek(fp, offset, SEEK_SET);
      return;
    FailLoc:
      LogModule.report(logvisor::Error, _SYS_STR("unable to open '%s' for writing"), path.data());
      err = true;
    }
    ~WriteStream() { fclose(fp); }
    uint64_t write(const void* buf, uint64_t length) {
      if (m_maxWriteSize >= 0) {
        if (FTell(fp) + length > m_maxWriteSize) {
          LogModule.report(logvisor::Error, _SYS_STR("write operation exceeds file's %" PRIi64 "-byte limit"),
                           m_maxWriteSize);
          return 0;
        }
      }
      return fwrite(buf, 1, length, fp);
    }
  };
  std::unique_ptr<IWriteStream> beginWriteStream() const {
    bool Err = false;
    auto ret = std::unique_ptr<IWriteStream>(new WriteStream(m_path, m_maxWriteSize, Err));
    if (Err)
      return {};
    return ret;
  }
  std::unique_ptr<IWriteStream> beginWriteStream(uint64_t offset) const {
    bool Err = false;
    auto ret = std::unique_ptr<IWriteStream>(new WriteStream(m_path, offset, m_maxWriteSize, Err));
    if (Err)
      return {};
    return ret;
  }

  struct ReadStream : public IFileIO::IReadStream {
    FILE* fp;
    ReadStream(SystemStringView path, bool& err) {
      fp = Fopen(path.data(), _SYS_STR("rb"));
      if (!fp) {
        err = true;
        LogModule.report(logvisor::Error, _SYS_STR("unable to open '%s' for reading"), path.data());
      }
    }
    ReadStream(SystemStringView path, uint64_t offset, bool& err) : ReadStream(path, err) {
      if (err)
        return;
      FSeek(fp, offset, SEEK_SET);
    }
    ~ReadStream() { fclose(fp); }
    void seek(int64_t offset, int whence) { FSeek(fp, offset, whence); }
    uint64_t position() const { return FTell(fp); }
    uint64_t read(void* buf, uint64_t length) { return fread(buf, 1, length, fp); }
    uint64_t copyToDisc(IPartWriteStream& discio, uint64_t length) {
      uint64_t written = 0;
      uint8_t buf[0x7c00];
      while (length) {
        uint64_t thisSz = nod::min(uint64_t(0x7c00), length);
        if (read(buf, thisSz) != thisSz) {
          LogModule.report(logvisor::Error, "unable to read enough from file");
          return written;
        }
        if (discio.write(buf, thisSz) != thisSz) {
          LogModule.report(logvisor::Error, "unable to write enough to disc");
          return written;
        }
        length -= thisSz;
        written += thisSz;
      }
      return written;
    }
  };
  std::unique_ptr<IReadStream> beginReadStream() const {
    bool Err = false;
    auto ret = std::unique_ptr<IReadStream>(new ReadStream(m_path, Err));
    if (Err)
      return {};
    return ret;
  }
  std::unique_ptr<IReadStream> beginReadStream(uint64_t offset) const {
    bool Err = false;
    auto ret = std::unique_ptr<IReadStream>(new ReadStream(m_path, offset, Err));
    if (Err)
      return {};
    return ret;
  }
};

std::unique_ptr<IFileIO> NewFileIO(SystemStringView path, int64_t maxWriteSize) {
  return std::unique_ptr<IFileIO>(new FileIOFILE(path, maxWriteSize));
}

} // namespace nod
