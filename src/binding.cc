#include <node.h>
#include <node_buffer.h>
#include <nan.h>

#include <linux/landlock.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifndef __linux__
#  error "This addon only supports Linux"
#endif

#include "kernel.h"

using namespace node;
using namespace v8;
using namespace std;

bool uint64_value(Local<Value> val, __u64* out) {
  if (val->IsUint32()) {
    *out = Nan::To<uint32_t>(val).FromJust();
    return true;
  } else if (val->IsNumber()) {
    *out = Nan::To<int64_t>(val).FromJust();
    return true;
  } else if (val->IsBigInt()) {
    bool lossless;
    uint64_t tmp = val->ToBigInt(
      Nan::GetCurrentContext()
    ).ToLocalChecked()->Uint64Value(&lossless);
    if (lossless) {
      *out = tmp;
      return true;
    }
  }
  return false;
}

NAN_METHOD(CreateRuleset) {
  struct linux_landlock_ruleset_attr ruleset;
  memset(&ruleset, 0, sizeof(ruleset));

  if (info.Length() < 1)
    return Nan::ThrowError("Missing fs access argument");
  if (!uint64_value(info[0], &ruleset.handled_access_fs))
    return Nan::ThrowError("Invalid fs access argument");

  if (info.Length() > 1) {
    if (!uint64_value(info[1], &ruleset.handled_access_net))
      return Nan::ThrowError("Invalid net access argument");
  }

  if (info.Length() > 2) {
    if (!uint64_value(info[2], &ruleset.scoped))
      return Nan::ThrowError("Invalid scoped argument");
  }

  int fd = linux_landlock_create_ruleset(&ruleset, sizeof(ruleset), 0);
  if (fd < 0) {
    Nan::ThrowError(Nan::ErrnoException(errno, "landlock_create_ruleset"));
    return;
  }
  info.GetReturnValue().Set(Nan::New(fd));
}

NAN_METHOD(Close) {
  if (info.Length() < 1)
    return Nan::ThrowError("Missing fd argument");
  if (!info[0]->IsInt32())
    return Nan::ThrowTypeError("Invalid fd argument");

  int fd = Nan::To<int32_t>(info[0]).FromJust();
  if (fd < 0)
    return Nan::ThrowError("Invalid fd argument");

  int ret = close(fd);
  if (ret == -1)
    Nan::ThrowError(Nan::ErrnoException(errno, "close"));
}

NAN_METHOD(AddRule) {
  if (info.Length() < 1)
    return Nan::ThrowError("Missing fd argument");
  if (!info[0]->IsInt32())
    return Nan::ThrowTypeError("Invalid fd argument");

  int fd = Nan::To<int32_t>(info[0]).FromJust();
  if (fd < 0)
    return Nan::ThrowError("Invalid fd argument");

  enum linux_landlock_rule_type rule_type;
  if (info.Length() < 2)
    return Nan::ThrowError("Missing ruleType argument");
  if (info[1]->IsUint32()) {
    rule_type = static_cast<enum linux_landlock_rule_type>(
      Nan::To<uint32_t>(info[1]).FromJust()
    );
  } else if (info[1]->IsBigInt()) {
    bool lossless;
    uint64_t val = info[1]->ToBigInt(
      Nan::GetCurrentContext()
    ).ToLocalChecked()->Uint64Value(&lossless);
    if (!lossless || val > static_cast<uint64_t>((1UL << 32) - 1))
      return Nan::ThrowTypeError("Invalid ruleType argument");
    rule_type = static_cast<enum linux_landlock_rule_type>(val);
  } else {
    return Nan::ThrowTypeError("Invalid ruleType argument");
  }

  int ret;
  switch (rule_type) {
    case LINUX_LANDLOCK_RULE_PATH_BENEATH: {
      struct linux_landlock_path_beneath_attr attr;
      memset(&attr, 0, sizeof(attr));

      __u64 allowed_access;
      if (info.Length() < 3)
        return Nan::ThrowError("Missing allowedAccess argument");
      // Note: we can't pass `&attr.allowed_access` because the struct is
      //       packed, causing compilers to emit a warning
      if (!uint64_value(info[2], &allowed_access))
        return Nan::ThrowError("Invalid allowedAccess argument");
      attr.allowed_access = allowed_access;

      bool need_close = false;
      if (info.Length() < 4)
        return Nan::ThrowError("Missing parent argument");
      if (info[3]->IsString()) {
        // path
        Nan::Utf8String path_val(info[3]);
        const char* path = *path_val;
        if (!path)
          return Nan::ThrowError("Invalid parent string argument");

        attr.parent_fd = open(path, O_PATH | O_CLOEXEC);
        if (attr.parent_fd < 0)
          return Nan::ThrowError(Nan::ErrnoException(errno, "open"));
        need_close = true;
      } else if (info[3]->IsInt32()) {
        // fd
        attr.parent_fd = Nan::To<int32_t>(info[3]).FromJust();
        if (attr.parent_fd < 0)
          return Nan::ThrowError("Invalid parent argument");
      } else {
        return Nan::ThrowTypeError(
          "parent argument must be file descriptor or path"
        );
      }

      ret = linux_landlock_add_rule(fd, rule_type, &attr, 0);
      if (need_close)
        close(attr.parent_fd);
      break;
    }
    case LINUX_LANDLOCK_RULE_NET_PORT: {
      struct linux_landlock_net_port_attr attr;
      memset(&attr, 0, sizeof(attr));

      if (info.Length() < 3)
        return Nan::ThrowError("Missing allowedAccess argument");
      if (!uint64_value(info[2], &attr.allowed_access))
        return Nan::ThrowError("Invalid allowedAccess argument");

      if (info.Length() < 4)
        return Nan::ThrowError("Missing port argument");
      if (!info[3]->IsUint32())
        return Nan::ThrowTypeError("Invalid port argument");
      attr.port = Nan::To<uint32_t>(info[3]).FromJust();
      if (attr.port > 65535)
        return Nan::ThrowRangeError("Invalid port argument");

      ret = linux_landlock_add_rule(fd, rule_type, &attr, 0);
      break;
    }
    default:
      return Nan::ThrowError("Unsupported ruleType argument");
  }
  if (ret == -1)
    Nan::ThrowError(Nan::ErrnoException(errno, "landlock_add_rule"));
}

NAN_METHOD(RestrictSelf) {
  if (info.Length() < 1)
    return Nan::ThrowError("Missing fd argument");
  if (!info[0]->IsInt32())
    return Nan::ThrowTypeError("Invalid fd argument");

  int fd = Nan::To<int32_t>(info[0]).FromJust();
  if (fd < 0)
    return Nan::ThrowError("Invalid fd argument");

  __u32 flags = 0;
  if (info.Length() > 1) {
    if (info[1]->IsBigInt()) {
      bool lossless;
      uint64_t val = info[1]->ToBigInt(
        Nan::GetCurrentContext()
      ).ToLocalChecked()->Uint64Value(&lossless);
      if (!lossless || val > static_cast<uint64_t>((1UL << 32) - 1))
        return Nan::ThrowTypeError("Invalid flags argument");
      flags = val;
    } else if (info[1]->IsUint32()) {
      flags = Nan::To<uint32_t>(info[1]).FromJust();
    } else {
      return Nan::ThrowTypeError("Invalid flags argument");
    }
  }

  int ret = linux_landlock_restrict_self(fd, flags);
  if (ret == -1)
    Nan::ThrowError(Nan::ErrnoException(errno, "landlock_restrict_self"));
}

NAN_METHOD(GetABI) {
  long abi =
    linux_landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 0) {
    Nan::ThrowError(Nan::ErrnoException(errno, "landlock_create_ruleset"));
    return;
  }
  info.GetReturnValue().Set(Nan::New(static_cast<uint32_t>(abi)));
}

NAN_METHOD(GetErrata) {
  long errata =
    linux_landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_ERRATA);
  if (errata < 0) {
    Nan::ThrowError(Nan::ErrnoException(errno, "landlock_create_ruleset"));
    return;
  }
  info.GetReturnValue().Set(BigInt::New(Isolate::GetCurrent(), errata));
}

NAN_METHOD(SetNoNewPrivs) {
  int ret = prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L);
  if (ret < 0) {
    Nan::ThrowError(Nan::ErrnoException(errno, "prctl(PR_SET_NO_NEW_PRIVS)"));
    return;
  }
}

NAN_MODULE_INIT(init) {
  Nan::Export(target, "addRule", AddRule);
  Nan::Export(target, "close", Close);
  Nan::Export(target, "createRuleset", CreateRuleset);
  Nan::Export(target, "getABI", GetABI);
  Nan::Export(target, "getErrata", GetErrata);
  Nan::Export(target, "restrictSelf", RestrictSelf);
  Nan::Export(target, "setNoNewPrivs", SetNoNewPrivs);

  Isolate* isolate = Isolate::GetCurrent();
  Local<Object> consts = Object::New(isolate, Nan::Null(), nullptr, nullptr, 0);
  Nan::Set(target, Nan::New("constants").ToLocalChecked(), consts);
#define SET_CONSTANT(name)                                                     \
  do {                                                                         \
    Nan::Set(                                                                  \
      consts,                                                                  \
      Nan::New(#name).ToLocalChecked(),                                        \
      BigInt::NewFromUnsigned(isolate, name)                                   \
    );                                                                         \
  } while (0)
  SET_CONSTANT(LANDLOCK_ACCESS_FS_EXECUTE);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_WRITE_FILE);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_READ_FILE);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_READ_DIR);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_REMOVE_DIR);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_REMOVE_FILE);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_MAKE_CHAR);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_MAKE_DIR);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_MAKE_REG);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_MAKE_SOCK);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_MAKE_FIFO);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_MAKE_BLOCK);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_MAKE_SYM);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_REFER);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_TRUNCATE);
  SET_CONSTANT(LANDLOCK_ACCESS_FS_IOCTL);

  SET_CONSTANT(LANDLOCK_ACCESS_NET_BIND_TCP);
  SET_CONSTANT(LANDLOCK_ACCESS_NET_CONNECT_TCP);

  SET_CONSTANT(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET);
  SET_CONSTANT(LANDLOCK_SCOPE_SIGNAL);

  SET_CONSTANT(LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF);
  SET_CONSTANT(LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON);
  SET_CONSTANT(LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF);
#undef SET_CONSTANT

#define SET_ENUM(name)                                                         \
  do {                                                                         \
    Nan::Set(                                                                  \
      consts,                                                                  \
      Nan::New(#name).ToLocalChecked(),                                        \
      BigInt::NewFromUnsigned(isolate, LINUX_##name)                           \
    );                                                                         \
  } while (0)
  SET_ENUM(LANDLOCK_RULE_PATH_BENEATH);
  SET_ENUM(LANDLOCK_RULE_NET_PORT);
#undef SET_ENUM
}

NAN_MODULE_WORKER_ENABLED(landlock, init)
