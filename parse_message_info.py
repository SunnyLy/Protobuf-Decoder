#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
解析MessageInfo字符串，还原proto结构
"""

def parse_message_info():
    """解析MessageInfo字符串"""
    print("=== 解析MessageInfo字符串 ===\n")
    
    # MessageInfo字符串
    message_info = "\u0001\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0001\u0001\u0001\u041B\u0002\u1009\u0000\u0003\u100A\u0001\u0004\u1002\u0002"
    
    # 字段名称数组
    field_names = ["b", "c", "cjgt_Group", "g", "d", "e"]
    
    print(f"MessageInfo字符串: {repr(message_info)}")
    print(f"字段名称数组: {field_names}")
    print()
    
    # 将字符串转换为字节
    data = message_info.encode('utf-16le')
    print(f"UTF-16LE字节数据: {data.hex()}")
    print()
    
    # 解析protobuf字段信息
    fields = parse_protobuf_fields(data)
    
    print("=== 解析结果 ===")
    print("message ciyk {")
    
    for i, field in enumerate(fields):
        field_name = field_names[i] if i < len(field_names) else f"field_{i+1}"
        field_type = get_protobuf_type(field['type'])
        field_number = field['number']
        
        # 处理特殊类型
        if field_name == "cjgt_Group":
            field_type = "cjgt_Group"
        elif field_name == "g":
            field_type = "cagw"
        
        # 判断是否为repeated
        is_repeated = field.get('repeated', False)
        repeated_keyword = "repeated " if is_repeated else "optional "
        
        print(f"\t{repeated_keyword}{field_type} {field_name} = {field_number};")
    
    print("}")

def parse_protobuf_fields(data):
    """解析protobuf字段信息"""
    fields = []
    pos = 0
    
    while pos < len(data):
        if pos >= len(data):
            break
        
        # 读取字段信息
        field_info = {}
        
        # 读取字段号
        if pos < len(data):
            field_number = data[pos]
            field_info['number'] = field_number
            pos += 1
        
        # 读取字段类型信息
        if pos < len(data):
            type_info = data[pos]
            field_info['type'] = type_info
            pos += 1
            
            # 检查是否为repeated字段
            if type_info == 0x04:  # 0x04通常表示repeated
                field_info['repeated'] = True
            else:
                field_info['repeated'] = False
        
        # 跳过其他信息
        while pos < len(data) and data[pos] == 0:
            pos += 1
        
        fields.append(field_info)
    
    return fields

def get_protobuf_type(type_code):
    """根据类型代码获取protobuf类型"""
    type_mapping = {
        0x01: "int32",
        0x02: "int64", 
        0x03: "uint32",
        0x04: "repeated",
        0x05: "string",
        0x06: "bytes",
        0x07: "bool",
        0x08: "double",
        0x09: "float",
        0x0A: "message"
    }
    
    return type_mapping.get(type_code, f"unknown_{type_code}")

if __name__ == "__main__":
    parse_message_info()
