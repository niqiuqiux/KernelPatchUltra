/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2025 niqiuqiux. All Rights Reserved.
 */


#include "baselib.h"
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "uapi/linux/btf.h"


 /* 对齐函数 */
 static inline uint64_t align_ceil(uint64_t x, uint64_t align)
 {
     return ((x) + (align) - 1) & ~((align) - 1);
 }
 
 #define BTF_ALIGN(x) align_ceil(x, 4)
 
 /* 前置声明，避免早期调用产生隐式声明 */
 static int parse_btf_header(const char *data, uint32_t data_size, struct btf_header **hdr);
 static int parse_btf_types(const btf_t *btf, const struct btf_type ***types, uint32_t *nr_types);
 
 /* 从内核虚拟地址空间获取BTF数据 */
 static int find_btf_in_kernel_vaddr(const char **btf_data, uint32_t *btf_size)
 {
     /* 获取BTF section的起始和结束地址 */
     unsigned long start_addr = kallsyms_lookup_name("__start_BTF");
     unsigned long stop_addr = kallsyms_lookup_name("__stop_BTF");
 
     if (!start_addr || !stop_addr) {
         logkw("BTF symbols not found (__start_BTF=%lx, __stop_BTF=%lx)\n", start_addr, stop_addr);
         return -1;
     }
 
     if (stop_addr <= start_addr) {
         logke("invalid BTF section range: start=%lx, stop=%lx\n", start_addr, stop_addr);
         return -1;
     }
 
     *btf_data = (const char *)start_addr;
     *btf_size = (uint32_t)(stop_addr - start_addr);
 
    logki("found BTF in kernel vaddr: start=0x%lx, stop=0x%lx, size=0x%x\n", 
          start_addr, stop_addr, *btf_size);
 
     return 0;
 }
 
 /* 统一的数据解析入口 */
 static int btf_parse_from_data(const char *btf_data, uint32_t btf_size, btf_t *btf)
 {
     btf->data = btf_data;
     btf->data_size = btf_size;
 
     if (parse_btf_header(btf_data, btf_size, &btf->hdr) != 0) {
         return -1;
     }
 
     /* 直接读取header字段 */
     uint32_t hdr_len = btf->hdr->hdr_len;
     uint32_t str_off = btf->hdr->str_off;
 
     /* 验证字符串表偏移和大小 */
     uint32_t str_len = btf->hdr->str_len;
     if (hdr_len + str_off + str_len > btf_size) {
         logke("string table extends beyond BTF data: hdr_len=%u, str_off=%u, str_len=%u, btf_size=%u\n",
                    hdr_len, str_off, str_len, btf_size);
         return -1;
     }
 
     btf->strings = btf_data + hdr_len + str_off;
     if (str_len > 0 && btf->strings[0] != '\0') {
         logkw("string table does not start with null character\n");
     }
 
     /* 解析类型表 */
     if (parse_btf_types(btf, &btf->types, &btf->nr_types) != 0) {
         return -1;
     }
 
     logki("parsed BTF successfully\n");
     return 0;
 }
  
  /* 解析BTF头部 */
  static int parse_btf_header(const char *data, uint32_t data_size, struct btf_header **hdr)
  {
      if (data_size < sizeof(struct btf_header)) {
          logke("BTF data too small for header\n");
          return -1;
      }
  
      *hdr = (struct btf_header *)data;
  
      /* 直接读取magic number */
      uint16_t magic = (*hdr)->magic;
  
      if (magic != BTF_MAGIC) {
          logke("invalid BTF magic: 0x%04x\n", magic);
          return -1;
      }
  
      /* 检查版本 */
      uint8_t version = (*hdr)->version;
      if (version != BTF_VERSION) {
          logkw("unsupported BTF version: %d\n", version);
      }
  
      /* 直接读取字段 */
      uint32_t hdr_len = (*hdr)->hdr_len;
      uint32_t type_len = (*hdr)->type_len;
      uint32_t str_len = (*hdr)->str_len;
  
      /* 检查数据大小 */
      uint32_t total_size = hdr_len + type_len + str_len;
      if (data_size < total_size) {
          logke("BTF data size mismatch: expected %u, got %u\n", total_size, data_size);
          return -1;
      }
  
      logki("BTF header: magic=0x%04x, version=%d, type_len=%u, str_len=%u\n", 
                 magic, version, type_len, str_len);
  
      return 0;
  }
  
  /* 解析BTF类型表 */
  static int parse_btf_types(const btf_t *btf, const struct btf_type ***types, uint32_t *nr_types)
  {
      if (!btf || !btf->hdr || !btf->data) {
          logke("parse_btf_types: invalid btf or hdr\n");
          return -1;
      }
      
      const struct btf_header *hdr = btf->hdr;
      
      /* 直接读取header字段 */
      uint32_t hdr_len = hdr->hdr_len;
      uint32_t type_off = hdr->type_off;
      uint32_t type_len = hdr->type_len;
      
      const char *type_data = btf->data + hdr_len + type_off;
      uint32_t type_count = 0;
      uint32_t offset = 0;
  
      logki("parsing BTF types: hdr_len=%u, type_off=%u, type_len=%u\n", hdr_len, type_off, type_len);
  
     /* 第一遍：计算类型数量 */
     while (offset < type_len) {
         /* 检查是否有足够的空间读取一个btf_type结构 */
         if (offset + sizeof(struct btf_type) > type_len) {
             /* 如果剩余字节不足以读取完整结构，说明类型表已结束 */
             /* 这可能是正常的，因为类型表可能不是完全对齐的 */
             if (type_len - offset > 0) {
                 logki("type table ends with %u trailing bytes at offset %u\n", type_len - offset, offset);
             }
             break;
         }
          
          const struct btf_type *t = (const struct btf_type *)(type_data + offset);
          
          /* 直接读取info字段 */
          uint32_t info = t->info;
          
          uint32_t kind = BTF_INFO_KIND(info);
          uint32_t vlen = BTF_INFO_VLEN(info);
 
          /* 调试：打印前几个类型的信息 */
          if (type_count < 5) {
              uint32_t name_off = t->name_off;
              logki("type[%u]: kind=%u, vlen=%u, name_off=%u, offset=%u\n", 
                         type_count, kind, vlen, name_off, offset);
          }
  
          /* kind == 0 是void类型，仍然是有效类型，不应该break */
          /* 类型表的结束应该通过offset >= type_len来判断 */
  
          offset += sizeof(struct btf_type);
          uint32_t old_offset = offset;
  
          /* 根据类型添加额外数据大小 */
          switch (kind) {
          case BTF_KIND_INT:
              if (offset + sizeof(uint32_t) <= type_len) {
                  offset += sizeof(uint32_t); /* encoding */
              } else {
                  goto type_parse_done;
              }
              break;
          case BTF_KIND_ARRAY:
              if (offset + sizeof(struct btf_array) <= type_len) {
                  offset += sizeof(struct btf_array);
              } else {
                  goto type_parse_done;
              }
              break;
          case BTF_KIND_STRUCT:
          case BTF_KIND_UNION:
              if (offset + vlen * sizeof(struct btf_member) <= type_len) {
                  offset += vlen * sizeof(struct btf_member);
              } else {
                  goto type_parse_done;
              }
              break;
          case BTF_KIND_ENUM:
              if (offset + vlen * sizeof(struct btf_enum) <= type_len) {
                  offset += vlen * sizeof(struct btf_enum);
              } else {
                  goto type_parse_done;
              }
              break;
          case BTF_KIND_ENUM64:
              if (offset + vlen * sizeof(struct btf_enum64) <= type_len) {
                  offset += vlen * sizeof(struct btf_enum64);
              } else {
                  goto type_parse_done;
              }
              break;
          case BTF_KIND_FUNC_PROTO:
              if (offset + vlen * sizeof(struct btf_param) <= type_len) {
                  offset += vlen * sizeof(struct btf_param);
              } else {
                  goto type_parse_done;
              }
              break;
          case BTF_KIND_VAR:
              if (offset + sizeof(uint32_t) <= type_len) {
                  offset += sizeof(uint32_t); /* linkage */
              } else {
                  goto type_parse_done;
              }
              break;
          case BTF_KIND_DATASEC:
              if (offset + vlen * sizeof(struct btf_var_secinfo) <= type_len) {
                  offset += vlen * sizeof(struct btf_var_secinfo);
              } else {
                  goto type_parse_done;
              }
              break;
          default:
              /* 未知类型，只跳过基本结构 */
              break;
          }
  
          /* 如果offset超出范围，说明数据有问题 */
          if (offset > type_len) {
              logkw("type record extends beyond type_len at offset %u (kind=%u, vlen=%u)\n", 
                         old_offset, kind, vlen);
              goto type_parse_done;
          }
  
         /* 对齐offset，但要确保不超过type_len */
         uint32_t aligned_offset = BTF_ALIGN(offset);
         if (aligned_offset > type_len) {
             /* 对齐后的offset超出范围，说明这是最后一个类型 */
             aligned_offset = type_len;
         }
         offset = aligned_offset;
         type_count++;
         
         /* 防止无限循环 */
         if (type_count > 1000000) {
             logke("too many types, possible infinite loop\n");
             break;
         }
         
         /* 每10000个类型打印一次进度 */
         // if (type_count % 10000 == 0) {
         //    logki("parsed %u types, offset=%u/%u\n", type_count, offset, type_len);
         // }
         
         /* 如果offset已经达到或超过type_len，结束解析 */
         if (offset >= type_len) {
             break;
         }
     }
 type_parse_done:
     /* label needs a statement; use empty statement to keep following declarations valid */
     ;
 
     uint32_t expected_type_count = type_count;
      *nr_types = type_count;
      if (type_count == 0) {
          *types = NULL;
          return 0;
      }
 
      /* 分配类型指针数组 */
      *types = (const struct btf_type **)vmalloc((type_count + 1) * sizeof(struct btf_type *));
      if (!*types) {
          logke("failed to allocate type array\n");
          return -1;
      }
 
     /* 第二遍：填充类型指针 */
     offset = 0;
     type_count = 0;
     while (offset < type_len) {
         /* 检查是否有足够的空间读取一个btf_type结构 */
         if (offset + sizeof(struct btf_type) > type_len) {
             /* 类型表结束 */
             break;
         }
          
          const struct btf_type *t = (const struct btf_type *)(type_data + offset);
          
          /* 直接读取info字段 */
          uint32_t info = t->info;
          
          uint32_t kind = BTF_INFO_KIND(info);
          uint32_t vlen = BTF_INFO_VLEN(info);
  
          /* kind == 0 是void类型，仍然是有效类型 */
          type_count++;
          /* 检查数组越界 */
          if (type_count > expected_type_count) {
              logke("type_count %u exceeds expected %u, possible array overflow\n", type_count, expected_type_count);
              break;
          }
          (*types)[type_count] = t; /* 类型ID从1开始 */

          offset += sizeof(struct btf_type);
  
          /* 根据类型添加额外数据大小 */
          switch (kind) {
          case BTF_KIND_INT:
              if (offset + sizeof(uint32_t) > type_len) goto done;
              offset += sizeof(uint32_t);
              break;
          case BTF_KIND_ARRAY:
              if (offset + sizeof(struct btf_array) > type_len) goto done;
              offset += sizeof(struct btf_array);
              break;
          case BTF_KIND_STRUCT:
          case BTF_KIND_UNION:
              if (offset + vlen * sizeof(struct btf_member) > type_len) goto done;
              offset += vlen * sizeof(struct btf_member);
              break;
          case BTF_KIND_ENUM:
              if (offset + vlen * sizeof(struct btf_enum) > type_len) goto done;
              offset += vlen * sizeof(struct btf_enum);
              break;
          case BTF_KIND_ENUM64:
              if (offset + vlen * sizeof(struct btf_enum64) > type_len) goto done;
              offset += vlen * sizeof(struct btf_enum64);
              break;
          case BTF_KIND_FUNC_PROTO:
              if (offset + vlen * sizeof(struct btf_param) > type_len) goto done;
              offset += vlen * sizeof(struct btf_param);
              break;
          case BTF_KIND_VAR:
              if (offset + sizeof(uint32_t) > type_len) goto done;
              offset += sizeof(uint32_t);
              break;
          case BTF_KIND_DATASEC:
              if (offset + vlen * sizeof(struct btf_var_secinfo) > type_len) goto done;
              offset += vlen * sizeof(struct btf_var_secinfo);
              break;
          default:
              /* 未知类型，只跳过基本结构 */
              break;
          }
  
           /* 如果offset超出范围，说明数据有问题 */
           if (offset > type_len) {
               logkw("type record extends beyond type_len at offset %u\n", offset);
               break;
           }
 
           /* 对齐offset，但要确保不超过type_len */
           uint32_t aligned_offset = BTF_ALIGN(offset);
           if (aligned_offset > type_len) {
               aligned_offset = type_len;
           }
           offset = aligned_offset;
           
           /* 防止无限循环 */
           if (type_count > 1000000) {
               logke("too many types, possible infinite loop\n");
               break;
           }
           
           /* 如果offset已经达到或超过type_len，结束解析 */
           if (offset >= type_len) {
               break;
           }
       }
 done:
  
      /* 验证第二遍解析的类型数量与第一遍一致 */
      if (type_count != expected_type_count) {
          logke("type count mismatch: first pass=%u, second pass=%u\n", expected_type_count, type_count);
          /* 使用实际解析的类型数量 */
          *nr_types = type_count;
      }
      
      logki("parsed %u BTF types (validated %u types in second pass)\n", *nr_types, type_count);
      return 0;
  }
  
  /* 解析BTF - 从内核虚拟地址空间访问 */
  int32_t btf_parse(btf_t *btf)
  {
      if (!btf) {
          return -1;
      }
 
      lib_memset(btf, 0, sizeof(btf_t));
 
      /* 从内核虚拟地址空间获取BTF数据 */
      const char *btf_data = NULL;
      uint32_t btf_size = 0;
      if (find_btf_in_kernel_vaddr(&btf_data, &btf_size) != 0) {
          return -1;
      }
 
      return btf_parse_from_data(btf_data, btf_size, btf);
 }
  
  /* 释放BTF资源 */
  void btf_free(btf_t *btf)
  {
      if (!btf) {
          return;
      }
 
      /* 只释放动态分配的类型指针数组 */
      if (btf->types) {
          vfree((void *)btf->types);
          btf->types = NULL;
      }
 
      /* 注意：data、hdr、strings 指向内核虚拟地址空间，不需要释放 */
      lib_memset(btf, 0, sizeof(btf_t));
  }
  
  /* 根据类型ID获取类型 */
  const struct btf_type *btf_type_by_id(const btf_t *btf, uint32_t type_id)
  {
      if (!btf || !btf->types || type_id == 0 || type_id > btf->nr_types) {
          return NULL;
      }
      return btf->types[type_id];
  }
  
  /* 根据偏移获取名称 */
  const char *btf_name_by_offset(const btf_t *btf, uint32_t name_off)
  {
      if (!btf || !btf->strings) {
          return NULL;
      }
      
      /* 直接读取str_len */
      uint32_t str_len = btf->hdr->str_len;
      
      /* 边界检查 */
      if (name_off >= str_len) {
          return NULL;
      }
      
      /* 如果偏移为0，返回NULL（BTF规范：偏移0表示无名称） */
      if (name_off == 0) {
          return NULL;
      }
      
      /* 验证字符串不会超出字符串表边界 */
      const char *name = btf->strings + name_off;
      const char *str_end = btf->strings + str_len;
      
      /* 确保name指针在有效范围内 */
      if (name >= str_end) {
          return NULL;
      }
      
      /* 检查字符串是否为空 */
      if (name[0] == '\0') {
          return NULL;
      }
      
      /* 检查字符串是否以null结尾（查找null终止符），限制最大搜索长度避免无限循环 */
      const char *p = name;
      uint32_t max_len = str_end - name;
      uint32_t searched = 0;
      while (searched < max_len && p < str_end) {
          if (*p == '\0') {
              /* 找到null终止符，字符串有效 */
              return name;
          }
          p++;
          searched++;
      }
      
      /* 如果没有找到null终止符，说明字符串无效 */
      return NULL;
  }
  
  /* 获取类型种类 - 注意：需要根据BTF的字节序读取 */
  uint32_t btf_kind(const struct btf_type *t)
  {
      if (!t) return BTF_KIND_UNKN;
 
      return BTF_INFO_KIND(t->info);
  }
  
  /* 获取可变长度字段数量 - 注意：需要根据BTF的字节序读取 */
  uint32_t btf_vlen(const struct btf_type *t)
  {
      if (!t) return 0;
      return BTF_INFO_VLEN(t->info);
  }
  
  
  /* 获取类型信息 */
  int32_t btf_get_type_info(const btf_t *btf, uint32_t type_id, btf_type_info_t *info)
  {
      if (!btf || !info) return -1;
  
      const struct btf_type *t = btf_type_by_id(btf, type_id);
      if (!t) return -1;
  
      /* 直接读取字段 */
      uint32_t name_off = t->name_off;
      uint32_t size_val = t->size;
 
      info->type_id = type_id;
      info->kind = BTF_INFO_KIND(t->info);
      info->name = btf_name_by_offset(btf, name_off);
      info->size = size_val;
      info->type_data = (void *)t;
  
      return 0;
  }
  
 /* 内部通用实现：可选检查 kind，避免重复代码，同时避免过多调试输出 */
 static int32_t btf_find_by_name_internal(const btf_t *btf,
                                          const char *name,
                                          uint32_t expected_kind,
                                          bool check_kind)
 {
     if (!btf || !name || !btf->types || !btf->strings || btf->nr_types == 0)
         return -1;
 
     uint32_t str_len = btf->hdr->str_len;
     if (str_len == 0)
         return -1;
 
     for (uint32_t i = 1; i <= btf->nr_types; i++) {
         const struct btf_type *t = btf_type_by_id(btf, i);
         if (!t)
             continue;
 
         if (check_kind) {
             uint32_t kind = BTF_INFO_KIND(t->info);
             if (kind != expected_kind)
                 continue;
         }
 
         uint32_t name_off = t->name_off;
         if (name_off == 0 || name_off >= str_len)
             continue;
 
         const char *tname = btf_name_by_offset(btf, name_off);
         if (!tname)
             continue;
 
         if (lib_strcmp(tname, name) == 0)
             return (int32_t)i;
     }
 
     return -1;
 }
 
/* 跳过 typedef/const/volatile/restrict，获取真实结构/联合类型 ID；若遇到指针返回 false */
static bool resolve_struct_or_union_type_id(const btf_t *btf, uint32_t type_id, uint32_t *resolved_id)
{
    uint32_t depth = 0;
    const uint32_t MAX_DEPTH = 6; /* 防止循环引用导致的无限循环 */

    while (depth < MAX_DEPTH) {
        const struct btf_type *t = btf_type_by_id(btf, type_id);
        if (!t)
            return false;

        uint32_t kind = BTF_INFO_KIND(t->info);
        switch (kind) {
        case BTF_KIND_TYPEDEF:
        case BTF_KIND_VOLATILE:
        case BTF_KIND_CONST:
        case BTF_KIND_RESTRICT:
            type_id = *(uint32_t *)(t + 1);
            depth++;
            continue;
        case BTF_KIND_PTR:
            return false;
        case BTF_KIND_STRUCT:
        case BTF_KIND_UNION:
            if (resolved_id)
                *resolved_id = type_id;
            return true;
        default:
            return false;
        }
    }

    /* 超过最大深度，可能存在循环引用 */
    logkw("resolve_struct_or_union_type_id: exceeded max depth %u\n", MAX_DEPTH);
    return false;
}
 
 /* 递归解析得到可用的 STRUCT/UNION 完整定义（处理 TYPEDEF/FWD/不完整定义），失败返回 -1 */
 static int32_t btf_find_complete_struct_id(const btf_t *btf, uint32_t type_id, int depth)
 {
     if (!btf || depth > 8) /* 避免极端递归 */
         return -1;
 
     const struct btf_type *t = btf_type_by_id(btf, type_id);
     if (!t)
         return -1;
 
     uint32_t kind = BTF_INFO_KIND(t->info);
 
     /* 先处理可以直接跳转的包装类型 */
     switch (kind) {
     case BTF_KIND_TYPEDEF:
     case BTF_KIND_VOLATILE:
     case BTF_KIND_CONST:
     case BTF_KIND_RESTRICT:
         return btf_find_complete_struct_id(btf, *(uint32_t *)(t + 1), depth + 1);
     case BTF_KIND_STRUCT:
     case BTF_KIND_UNION:
         /* 已是结构/联合类型，如 vlen>0 且 size>0 视为完整 */
         if (BTF_INFO_VLEN(t->info) > 0 && t->size > 0)
             return (int32_t)type_id;
         break; /* 继续按名称搜寻完整定义 */
     case BTF_KIND_FWD:
         break; /* 统一走名字匹配逻辑 */
     default:
         return -1;
     }
 
     /* 按名称查找同名且有完整定义的结构体 */
     const char *name = btf_name_by_offset(btf, t->name_off);
     if (!name)
         return -1;
 
     for (uint32_t i = 1; i <= btf->nr_types; i++) {
         if (i == type_id)
             continue;
 
         const struct btf_type *cand = btf_type_by_id(btf, i);
         if (!cand)
             continue;
 
         uint32_t ck = BTF_INFO_KIND(cand->info);
         if (ck != BTF_KIND_STRUCT && ck != BTF_KIND_UNION)
             continue;
 
         const char *cname = btf_name_by_offset(btf, cand->name_off);
         if (!cname || lib_strcmp(name, cname) != 0)
             continue;
 
         if (cand->size > 0 && BTF_INFO_VLEN(cand->info) > 0)
             return (int32_t)i;
     }
 
     return -1;
 }
 
 /* 根据名称查找类型（不限制 kind） */
 int32_t btf_find_by_name(const btf_t *btf, const char *name)
 {
     return btf_find_by_name_internal(btf, name, 0, false);
 }
 
 /* 根据名称 + kind 查找类型，kind 取值为 BTF_KIND_xxx */
 int32_t btf_find_by_name_kind(const btf_t *btf, const char *name, uint32_t kind)
 {
     return btf_find_by_name_internal(btf, name, kind, true);
 }
 
 /* 获取结构体成员 */
 __noinline  int32_t btf_get_struct_members(const btf_t *btf,
                                                 uint32_t struct_type_id,
                                                 btf_member_info_t *members,
                                                 int32_t max_members) {
 
     if (!btf || !members || max_members <= 0)
         return -1;
 
     int32_t resolved_id = btf_find_complete_struct_id(btf, struct_type_id, 0);
     if (resolved_id < 0)
         return -1;
 
     const struct btf_type *t = btf_type_by_id(btf, (uint32_t)resolved_id);
     if (!t)
         return -1;
 
     uint32_t info_raw = t->info;
     uint32_t vlen = BTF_INFO_VLEN(info_raw);
     if (vlen > (uint32_t)max_members)
         vlen = max_members;
 
     if (vlen == 0)
         return 0;
 
     const struct btf_member *m = (const struct btf_member *)(t + 1);
 
     for (uint32_t i = 0; i < vlen; i++) {
         uint32_t name_off = m[i].name_off;
         uint32_t type_id = m[i].type;
         uint32_t offset_val = m[i].offset;
 
         members[i].name = btf_name_by_offset(btf, name_off);
         members[i].type_id = type_id;
 
         /* 解析 offset/bitfield */
         uint32_t struct_kind_flag = BTF_INFO_KFLAG(info_raw);
         uint32_t bitfield_size = BTF_MEMBER_BITFIELD_SIZE(offset_val);
         uint32_t bit_offset = BTF_MEMBER_BIT_OFFSET(offset_val);
 
         if (struct_kind_flag && bitfield_size > 0) {
             members[i].bit_offset = bit_offset;
             members[i].offset = bit_offset / 8;
             members[i].bitfield_size = bitfield_size;
         } else {
             members[i].bit_offset = offset_val;
             members[i].offset = offset_val / 8;
             members[i].bitfield_size = 0;
         }
     }
 
     return (int32_t)vlen;
 }
 
 
 
 /* 根据结构体 type_id + 成员名查找成员信息（单层结构体，不递归） */
 int32_t btf_find_struct_member_by_type_id(const btf_t *btf,
                                           uint32_t struct_type_id,
                                           const char *member_name,
                                           btf_member_info_t *out)
 {
     if (!btf || !member_name || !out) {
         return -1;
     }
 
     /* 先取出该结构体的所有成员，然后在线性表中按名称搜索 */
     btf_member_info_t *members = NULL;
     int32_t count = btf_get_struct_members(btf, struct_type_id, members,
                                            0);
     /* 上面调用不分配空间，需要重新分配并获取 */
     count = 0; /* 重置以确保逻辑明确 */
     {
         /* 使用与 test.c 相同的动态分配策略，避免大结构体被截断 */
         uint32_t vlen_cap = 0;
         const struct btf_type *t = btf_type_by_id(btf, struct_type_id);
         if (!t)
             return -1;
         uint32_t vlen = BTF_INFO_VLEN(t->info);
         vlen_cap = vlen ? vlen : 256;
         if (vlen_cap > 4096)
             vlen_cap = 4096;
 
         //members = kcalloc(vlen_cap, sizeof(*members), GFP_KERNEL);
        members = vmalloc(vlen_cap * sizeof(*members));
         if (!members)
             return -1;
         lib_memset(members, 0, vlen_cap * sizeof(*members));
 
         count = btf_get_struct_members(btf, struct_type_id, members, vlen_cap);
         if (count <= 0) {
            vfree(members);
             return -1;
         }
     }
 
     for (int32_t i = 0; i < count; i++) {
         const char *name = members[i].name;
         if (name && lib_strcmp(name, member_name) == 0) {
             *out = members[i];
            vfree(members);
             return 0;
         }
     }
 
     /* 未命中：尝试在匿名 struct/union 成员中继续一层搜索 */
     for (int32_t i = 0; i < count; i++) {
         if (members[i].name) /* 只处理匿名成员 */
             continue;
 
         uint32_t nested_type_id;
         if (!resolve_struct_or_union_type_id(btf, members[i].type_id, &nested_type_id))
             continue;
 
         /* 动态分配嵌套成员缓冲区 */
         uint32_t nested_cap = 0;
         const struct btf_type *nt = btf_type_by_id(btf, nested_type_id);
         if (!nt)
             continue;
         uint32_t nested_vlen = BTF_INFO_VLEN(nt->info);
         nested_cap = nested_vlen ? nested_vlen : 256;
         if (nested_cap > 4096)
             nested_cap = 4096;
 
         //btf_member_info_t *nested = kcalloc(nested_cap, sizeof(*nested), GFP_KERNEL);
        btf_member_info_t *nested = vmalloc(nested_cap * sizeof(*nested));
         if (!nested)
             continue;
         lib_memset(nested, 0, nested_cap * sizeof(*nested));
 
         int32_t nested_cnt = btf_get_struct_members(btf, nested_type_id, nested, nested_cap);
         if (nested_cnt > 0) {
             for (int32_t j = 0; j < nested_cnt; j++) {
                 const char *n = nested[j].name;
                 if (!n)
                     continue;
                 if (lib_strcmp(n, member_name) != 0)
                     continue;
 
                 *out = nested[j];
                 out->offset += members[i].offset; /* 累加父级偏移 */
                vfree(nested);
                vfree(members);
                 return 0;
             }
         }
 
        vfree(nested);
     }
 
    vfree(members);
     return -1;
 }
 
 /* 根据结构体名称 + 成员名查找成员信息（内部先通过名称找到结构体，再复用上面的接口） */
 int32_t btf_find_struct_member(const btf_t *btf,
                                const char *struct_name,
                                const char *member_name,
                                btf_member_info_t *out)
 {
     if (!btf || !struct_name || !member_name || !out) {
         return -1;
     }
 
     /* 通过名称先找到一个类型 ID（可能是 STRUCT/UNION/TYPEDEF/FWD） */
     int32_t type_id = btf_find_by_name(btf, struct_name);
     if (type_id < 0) {
         return -1;
     }
 
     /* 让已有的 btf_get_struct_members() 去处理 TYPEDEF/FWD 等情况 */
     return btf_find_struct_member_by_type_id(btf, (uint32_t)type_id, member_name, out);
 }
 
/* 工具函数：根据当前类型 ID，解析去掉 TYPEDEF/CONST/VOLATILE
 * 等修饰符后的实际类型 ID */
static uint32_t btf_resolve_real_type_id(const btf_t *btf, uint32_t type_id) {
  uint32_t depth = 0;
  const uint32_t MAX_DEPTH = 6; /* 防止循环引用导致的无限循环 */

  while (depth < MAX_DEPTH) {
    const struct btf_type *t = btf_type_by_id(btf, type_id);
    if (!t)
      break;

    uint32_t kind = BTF_INFO_KIND(t->info);
    if (kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_VOLATILE ||
        kind == BTF_KIND_CONST || kind == BTF_KIND_RESTRICT) {
      /* 这些类型后面紧跟着一个 u32，表示真正的 type_id */
      uint32_t *type_ptr = (uint32_t *)(t + 1);
      uint32_t raw = *type_ptr;
      uint32_t next_id = raw;
      if (next_id == 0 || next_id == type_id)
        break;
      type_id = next_id;
      depth++;
      continue;
    }

    break;
  }

  if (depth >= MAX_DEPTH) {
    logkw("btf_resolve_real_type_id: exceeded max depth %u\n", MAX_DEPTH);
  }

  return type_id;
}
 
 /* 按 type_id + 路径（形如 "a.b.c"）解析嵌套成员最终 offset/type */
 int32_t btf_resolve_member_path_by_type_id(const btf_t *btf,
                                            uint32_t root_type_id,
                                            const char *path,
                                            btf_member_path_result_t *out)
 {
     if (!btf || !path || !out)
         return -1;
 
     /* 为了简单，限制路径段数量和单段长度 */
     enum { MAX_SEG = 32, MAX_SEG_LEN = 128 };
     char buf[1024];
 
     size_t path_len = lib_strlen(path);
     if (path_len == 0 || path_len >= sizeof(buf))
         return -1;
 
     lib_memcpy(buf, path, path_len + 1);
 
     char *segs[MAX_SEG];
     int seg_cnt = 0;
 
     char *saveptr = buf;
     char *token = lib_strsep(&saveptr, ".");
     while (token && seg_cnt < MAX_SEG) {
         if (lib_strlen(token) == 0 || lib_strlen(token) >= MAX_SEG_LEN)
             return -1;
         segs[seg_cnt++] = token;
         token = lib_strsep(&saveptr, ".");
     }
 
     if (seg_cnt == 0)
         return -1;
 
     uint32_t cur_type_id = btf_resolve_real_type_id(btf, root_type_id);
     uint32_t total_off = 0;
 
     for (int i = 0; i < seg_cnt; i++) {
         const struct btf_type *t = btf_type_by_id(btf, cur_type_id);
         if (!t)
             return -1;
 
         uint32_t kind = BTF_INFO_KIND(t->info);
         if (kind != BTF_KIND_STRUCT && kind != BTF_KIND_UNION)
             return -1;
 
         btf_member_info_t mi;
         if (btf_find_struct_member_by_type_id(btf, cur_type_id, segs[i], &mi) != 0)
             return -1;
 
         total_off += mi.offset;
         cur_type_id = btf_resolve_real_type_id(btf, mi.type_id);
     }
 
     out->final_type_id = cur_type_id;
     out->final_offset = total_off;
     return 0;
 }
 
 /* 按结构体名 + 路径解析嵌套成员最终 offset/type */
 int32_t btf_resolve_member_path(const btf_t *btf,
                                 const char *struct_name,
                                 const char *path,
                                 btf_member_path_result_t *out)
 {
     if (!btf || !struct_name || !path || !out)
         return -1;
 
     int32_t type_id = btf_find_by_name(btf, struct_name);
     if (type_id < 0)
         return -1;
 
     return btf_resolve_member_path_by_type_id(btf, (uint32_t)type_id, path, out);
 }
 
 /* 根据类型 ID 获取最终类型大小（自动跳过 typedef/修饰符） */
 int32_t btf_get_type_size_by_id(const btf_t *btf, uint32_t type_id, uint32_t *size_out)
 {
     if (!btf || !size_out)
         return -1;
 
     uint32_t real_id = btf_resolve_real_type_id(btf, type_id);
     const struct btf_type *t = btf_type_by_id(btf, real_id);
     if (!t)
         return -1;
 
     uint32_t kind = BTF_INFO_KIND(t->info);
 
     /* 只有部分 kind 的类型才有 size 含义 */
     switch (kind) {
     case BTF_KIND_INT:
     case BTF_KIND_STRUCT:
     case BTF_KIND_UNION:
     case BTF_KIND_ENUM:
     case BTF_KIND_DATASEC:
     case BTF_KIND_FLOAT:
     case BTF_KIND_ENUM64:
         break;
     default:
         return -1;
     }
 
     uint32_t size_val = t->size;
     *size_out = size_val;
     return 0;
 }
 
 /* 根据结构体名称获取结构体大小（支持 typedef 包装的结构体） */
 int32_t btf_get_struct_size(const btf_t *btf, const char *struct_name, uint32_t *size_out)
 {
     if (!btf || !struct_name || !size_out)
         return -1;
 
     /* 优先按 struct kind 查，避免同名的 enum/union 干扰 */
     int32_t type_id = btf_find_by_name_kind(btf, struct_name, BTF_KIND_STRUCT);
     if (type_id < 0) {
         /* 退一步：不限定 kind，交给 size 解析逻辑去做判断（兼容 typedef 等情况） */
         type_id = btf_find_by_name(btf, struct_name);
         if (type_id < 0)
             return -1;
     }
 
     return btf_get_type_size_by_id(btf, (uint32_t)type_id, size_out);
 }
 
 /* 根据 VAR 类型 ID 获取内核变量信息（名称 / 类型 / 大小 / linkage） */
 int32_t btf_get_var_info_by_id(const btf_t *btf, uint32_t var_type_id, btf_var_info_t *info)
 {
     if (!btf || !info)
         return -1;
 
     const struct btf_type *t = btf_type_by_id(btf, var_type_id);
     if (!t)
         return -1;
 
     uint32_t kind = BTF_INFO_KIND(t->info);
     if (kind != BTF_KIND_VAR)
         return -1;
 
     /* 变量名 */
     uint32_t name_off = t->name_off;
     const char *name = btf_name_by_offset(btf, name_off);
 
     /* 变量类型 ID（注意：t->type 也是按 BTF 字节序存放的） */
     uint32_t raw_type = t->type;
     uint32_t type_id = raw_type;
 
     /* 变量 linkage 信息 */
     const struct btf_var *var = (const struct btf_var *)(t + 1);
     uint32_t raw_linkage = var->linkage;
     uint32_t linkage = raw_linkage;
 
     /* 变量大小 = 其类型大小 */
     uint32_t size = 0;
     if (btf_get_type_size_by_id(btf, type_id, &size) != 0) {
         size = 0;
     }
 
     info->name = name;
     info->type_id = type_id;
     info->size = size;
     info->linkage = linkage;
     return 0;
 }
 
 /* 根据变量名获取内核变量信息（内部自动查找 BTF_KIND_VAR） */
 int32_t btf_get_var_info_by_name(const btf_t *btf, const char *var_name, btf_var_info_t *info)
 {
     if (!btf || !var_name || !info)
         return -1;
 
     int32_t var_id = btf_find_by_name_kind(btf, var_name, BTF_KIND_VAR);
     if (var_id < 0)
         return -1;
 
     return btf_get_var_info_by_id(btf, (uint32_t)var_id, info);
 }
 
 /* 获取枚举值 */
 int32_t btf_get_enum_values(const btf_t *btf, uint32_t enum_type_id, btf_enum_info_t *values, int32_t max_values)
 {
      if (!btf || !values || max_values <= 0) return -1;
  
      const struct btf_type *t = btf_type_by_id(btf, enum_type_id);
      if (!t) return -1;
  
      uint32_t kind = BTF_INFO_KIND(t->info);
      if (kind != BTF_KIND_ENUM) {
          return -1;
      }
  
      uint32_t vlen = BTF_INFO_VLEN(t->info);
      if (vlen > (uint32_t)max_values) {
          vlen = max_values;
      }
  
      const struct btf_enum *e = (const struct btf_enum *)(t + 1);
      for (uint32_t i = 0; i < vlen; i++) {
          /* 直接读取 */
          uint32_t name_off = e[i].name_off;
          int32_t val = e[i].val;
          
          values[i].name = btf_name_by_offset(btf, name_off);
          values[i].val = val;
      }
  
      return (int32_t)vlen;
 }
 
 /* 获取枚举64值 */
 int32_t btf_get_enum64_values(const btf_t *btf, uint32_t enum_type_id, btf_enum64_info_t *values, int32_t max_values)
 {
      if (!btf || !values || max_values <= 0) return -1;
  
      const struct btf_type *t = btf_type_by_id(btf, enum_type_id);
      if (!t) return -1;
  
      uint32_t kind = BTF_INFO_KIND(t->info);
      if (kind != BTF_KIND_ENUM64) {
          return -1;
      }
  
      uint32_t vlen = BTF_INFO_VLEN(t->info);
      if (vlen > (uint32_t)max_values) {
          vlen = max_values;
      }
  
      const struct btf_enum64 *e = (const struct btf_enum64 *)(t + 1);
      for (uint32_t i = 0; i < vlen; i++) {
          /* 直接读取 */
          uint32_t name_off = e[i].name_off;
          uint32_t val_lo32 = e[i].val_lo32;
          uint32_t val_hi32 = e[i].val_hi32;
          
          /* 组合64位值 */
          uint64_t val = ((uint64_t)val_hi32 << 32) | val_lo32;
          
          values[i].name = btf_name_by_offset(btf, name_off);
          values[i].val = val;
      }
  
      return (int32_t)vlen;
 }
 
 /* 根据数组类型 ID 获取数组信息 */
 int32_t btf_get_array_info(const btf_t *btf, uint32_t array_type_id, btf_array_info_t *info)
 {
     if (!btf || !info) return -1;
 
     const struct btf_type *t = btf_type_by_id(btf, array_type_id);
     if (!t) return -1;
 
     uint32_t kind = BTF_INFO_KIND(t->info);
     if (kind != BTF_KIND_ARRAY) {
         return -1;
     }
 
     const struct btf_array *arr = (const struct btf_array *)(t + 1);
     
     /* 直接读取 */
     uint32_t type_id = arr->type;
     uint32_t index_type_id = arr->index_type;
     uint32_t nelems = arr->nelems;
 
     info->type_id = type_id;
     info->index_type_id = index_type_id;
     info->nelems = nelems;
 
     return 0;
 }
 
 /* 根据指针类型 ID 获取指针指向的目标类型 ID */
 int32_t btf_get_ptr_target_type_id(const btf_t *btf, uint32_t ptr_type_id, uint32_t *target_type_id)
 {
     if (!btf || !target_type_id) return -1;
 
     const struct btf_type *t = btf_type_by_id(btf, ptr_type_id);
     if (!t) return -1;
 
     uint32_t kind = BTF_INFO_KIND(t->info);
     if (kind != BTF_KIND_PTR) {
         return -1;
     }
 
     /* 指针类型的 type 字段指向目标类型 */
     uint32_t raw_type = t->type;
     *target_type_id = raw_type;
 
     return 0;
 }
 
 /* 根据函数原型类型 ID 获取函数参数信息 */
 int32_t btf_get_func_proto_params(const btf_t *btf, uint32_t func_proto_type_id, btf_param_info_t *params, int32_t max_params)
 {
     if (!btf || !params || max_params <= 0) return -1;
 
     const struct btf_type *t = btf_type_by_id(btf, func_proto_type_id);
     if (!t) return -1;
 
     uint32_t kind = BTF_INFO_KIND(t->info);
     if (kind != BTF_KIND_FUNC_PROTO) {
         return -1;
     }
 
     uint32_t vlen = BTF_INFO_VLEN(t->info);
     if (vlen > (uint32_t)max_params) {
         vlen = max_params;
     }
 
     const struct btf_param *p = (const struct btf_param *)(t + 1);
     for (uint32_t i = 0; i < vlen; i++) {
         /* 直接读取 */
         uint32_t name_off = p[i].name_off;
         uint32_t type_id = p[i].type;
 
         params[i].name = btf_name_by_offset(btf, name_off);
         params[i].type_id = type_id;
     }
 
     return (int32_t)vlen;
 }
 
 /* 根据函数原型类型 ID 获取函数返回类型 ID */
 int32_t btf_get_func_proto_return_type_id(const btf_t *btf, uint32_t func_proto_type_id, uint32_t *return_type_id)
 {
     if (!btf || !return_type_id) return -1;
 
     const struct btf_type *t = btf_type_by_id(btf, func_proto_type_id);
     if (!t) return -1;
 
     uint32_t kind = BTF_INFO_KIND(t->info);
     if (kind != BTF_KIND_FUNC_PROTO) {
         return -1;
     }
 
     /* 函数原型的 type 字段指向返回类型 */
     uint32_t raw_type = t->type;
     *return_type_id = raw_type;
 
     return 0;
 }
 
 /* 根据整数类型 ID 获取整数编码信息 */
 int32_t btf_get_int_info(const btf_t *btf, uint32_t int_type_id, btf_int_info_t *info)
 {
     if (!btf || !info) return -1;
 
     const struct btf_type *t = btf_type_by_id(btf, int_type_id);
     if (!t) return -1;
 
     uint32_t kind = BTF_INFO_KIND(t->info);
     if (kind != BTF_KIND_INT) {
         return -1;
     }
 
     /* INT 类型后面跟着一个 uint32_t encoding 字段 */
     const uint32_t *encoding_ptr = (const uint32_t *)(t + 1);
     uint32_t encoding_val = *encoding_ptr;
 
     uint32_t encoding = BTF_INT_ENCODING(encoding_val);
     uint32_t offset = BTF_INT_OFFSET(encoding_val);
     uint32_t bits = BTF_INT_BITS(encoding_val);
 
     info->encoding = encoding;
     info->offset = offset;
     info->bits = bits;
     info->is_signed = (encoding & BTF_INT_SIGNED) != 0;
     info->is_char = (encoding & BTF_INT_CHAR) != 0;
     info->is_bool = (encoding & BTF_INT_BOOL) != 0;
 
     return 0;
 }
 
 /* 遍历所有类型，对每个类型调用回调函数 */
 int32_t btf_iterate_types(const btf_t *btf, btf_type_iter_cb_t callback, void *ctx)
 {
     if (!btf || !callback || !btf->types) return -1;
 
     for (uint32_t i = 1; i <= btf->nr_types; i++) {
         const struct btf_type *t = btf_type_by_id(btf, i);
         if (!t) continue;
 
         int ret = callback(btf, i, t, ctx);
         if (ret != 0) {
             /* 回调返回非0值表示停止遍历 */
             return ret;
         }
     }
 
     return 0;
 }
 
 /* 根据名称前缀查找类型（返回第一个匹配的类型 ID） */
 int32_t btf_find_by_name_prefix(const btf_t *btf, const char *prefix)
 {
     if (!btf || !prefix || !btf->types || !btf->strings || btf->nr_types == 0)
         return -1;
 
     uint32_t prefix_len = lib_strlen(prefix);
     if (prefix_len == 0)
         return -1;
 
     uint32_t str_len = btf->hdr->str_len;
     if (str_len == 0)
         return -1;
 
     for (uint32_t i = 1; i <= btf->nr_types; i++) {
         const struct btf_type *t = btf_type_by_id(btf, i);
         if (!t) continue;
 
         uint32_t name_off = t->name_off;
         if (name_off == 0 || name_off >= str_len)
             continue;
 
         const char *tname = btf_name_by_offset(btf, name_off);
         if (!tname)
             continue;
 
         if (lib_strncmp(tname, prefix, prefix_len) == 0)
             return (int32_t)i;
     }
 
     return -1;
 }
 
 /* 根据名称前缀和 kind 查找类型 */
 int32_t btf_find_by_name_prefix_kind(const btf_t *btf, const char *prefix, uint32_t kind)
 {
     if (!btf || !prefix || !btf->types || !btf->strings || btf->nr_types == 0)
         return -1;
 
     uint32_t prefix_len = lib_strlen(prefix);
     if (prefix_len == 0)
         return -1;
 
     uint32_t str_len = btf->hdr->str_len;
     if (str_len == 0)
         return -1;
 
     for (uint32_t i = 1; i <= btf->nr_types; i++) {
         const struct btf_type *t = btf_type_by_id(btf, i);
         if (!t) continue;
 
         uint32_t t_kind = BTF_INFO_KIND(t->info);
         if (t_kind != kind)
             continue;
 
         uint32_t name_off = t->name_off;
         if (name_off == 0 || name_off >= str_len)
             continue;
 
         const char *tname = btf_name_by_offset(btf, name_off);
         if (!tname)
             continue;
 
         if (lib_strncmp(tname, prefix, prefix_len) == 0)
             return (int32_t)i;
     }
 
     return -1;
 }
  
  