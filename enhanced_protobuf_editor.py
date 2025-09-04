#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版Protobuf数据编辑器
修复了解析问题，支持嵌套消息和更准确的字段类型识别
基于CyberChef的解析逻辑
"""

import base64
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
from typing import Dict, Any, List, Optional, Union
import re
from pathlib import Path
import struct
import binascii

class EnhancedProtobufEditor:
    """增强版Protobuf数据编辑器"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("增强版Protobuf数据编辑器 - 逆向工程工具")
        self.root.geometry("1400x900")
        
        # 数据存储
        self.parsed_data = {}
        self.original_data = b""
        self.field_definitions = {}  # 字段定义
        self.editable_data = {}  # 可编辑的数据
        
        # 创建UI
        self._create_ui()
        
        # 初始化字段类型映射
        self._init_field_types()
    
    def _init_field_types(self):
        """初始化字段类型映射"""
        self.field_types = {
            "varint": "VarInt (e.g. int32, bool)",
            "64bit": "64-bit (e.g. fixed64, double)",
            "32bit": "32-bit (e.g. fixed32, float)",
            "length_delimited": "L-delim (e.g. string, message)",
            "start_group": "Start group (deprecated)",
            "end_group": "End group (deprecated)"
        }
    
    def _create_ui(self):
        """创建用户界面"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # 标题
        title_label = ttk.Label(main_frame, text="增强版Protobuf数据编辑器", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # 输入区域
        self._create_input_section(main_frame)
        
        # 解析结果显示区域
        self._create_display_section(main_frame)
        
        # 按钮区域
        self._create_button_section(main_frame)
        
        # 状态栏
        self.status_var = tk.StringVar()
        self.status_var.set("就绪")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
    
    def _create_input_section(self, parent):
        """创建输入区域"""
        # 输入框架
        input_frame = ttk.LabelFrame(parent, text="输入数据", padding="10")
        input_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        
        # 创建Notebook用于不同输入方式
        input_notebook = ttk.Notebook(input_frame)
        input_notebook.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Base64输入标签页
        base64_frame = ttk.Frame(input_notebook)
        input_notebook.add(base64_frame, text="Base64")
        
        self.base64_text = scrolledtext.ScrolledText(base64_frame, height=6, wrap=tk.WORD)
        self.base64_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Hex输入标签页
        hex_frame = ttk.Frame(input_notebook)
        input_notebook.add(hex_frame, text="Hex")
        
        self.hex_text = scrolledtext.ScrolledText(hex_frame, height=6, wrap=tk.WORD)
        self.hex_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 输入按钮框架
        input_btn_frame = ttk.Frame(input_frame)
        input_btn_frame.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # 清空按钮
        clear_btn = ttk.Button(input_btn_frame, text="清空", command=self._clear_input)
        clear_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 从文件加载按钮
        load_btn = ttk.Button(input_btn_frame, text="从文件加载", command=self._load_from_file)
        load_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 示例数据按钮
        example_btn = ttk.Button(input_btn_frame, text="加载示例", command=self._load_example)
        example_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 转换按钮
        convert_btn = ttk.Button(input_btn_frame, text="Base64↔Hex", command=self._convert_format)
        convert_btn.pack(side=tk.LEFT)
    
    def _create_display_section(self, parent):
        """创建显示区域"""
        # 显示框架
        display_frame = ttk.LabelFrame(parent, text="解析结果", padding="10")
        display_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        display_frame.columnconfigure(0, weight=1)
        display_frame.rowconfigure(0, weight=1)
        
        # 创建Notebook用于标签页
        self.notebook = ttk.Notebook(display_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 结构化显示标签页
        self.structure_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.structure_frame, text="结构化显示")
        
        # 创建左右分割的框架
        structure_paned = ttk.PanedWindow(self.structure_frame, orient=tk.HORIZONTAL)
        structure_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 左侧：字段列表
        left_frame = ttk.Frame(structure_paned)
        structure_paned.add(left_frame, weight=1)
        
        ttk.Label(left_frame, text="字段列表", font=("Arial", 10, "bold")).pack(pady=(0, 5))
        
        # 字段列表
        self.field_listbox = tk.Listbox(left_frame)
        field_scrollbar = ttk.Scrollbar(left_frame, orient=tk.VERTICAL, command=self.field_listbox.yview)
        self.field_listbox.configure(yscrollcommand=field_scrollbar.set)
        
        self.field_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        field_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # 绑定选择事件
        self.field_listbox.bind("<<ListboxSelect>>", self._on_field_select)
        
        # 右侧：字段详情和编辑
        right_frame = ttk.Frame(structure_paned)
        structure_paned.add(right_frame, weight=2)
        
        ttk.Label(right_frame, text="字段详情", font=("Arial", 10, "bold")).pack(pady=(0, 5))
        
        # 字段详情显示
        self.field_details = scrolledtext.ScrolledText(right_frame, height=10, wrap=tk.WORD)
        self.field_details.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 编辑区域
        edit_frame = ttk.LabelFrame(right_frame, text="编辑字段值", padding="5")
        edit_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 编辑输入框
        self.edit_var = tk.StringVar()
        self.edit_entry = ttk.Entry(edit_frame, textvariable=self.edit_var)
        self.edit_entry.pack(fill=tk.X, pady=(0, 5))
        
        # 编辑按钮
        edit_btn_frame = ttk.Frame(edit_frame)
        edit_btn_frame.pack(fill=tk.X)
        
        ttk.Button(edit_btn_frame, text="更新值", command=self._update_field_value).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(edit_btn_frame, text="重置", command=self._reset_field_value).pack(side=tk.LEFT)
        
        # JSON显示标签页
        self.json_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.json_frame, text="JSON格式")
        
        self.json_text = scrolledtext.ScrolledText(self.json_frame, wrap=tk.WORD)
        self.json_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # MitmProxy风格显示标签页
        self.mitmproxy_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.mitmproxy_frame, text="MitmProxy风格")
        
        self.mitmproxy_text = scrolledtext.ScrolledText(self.mitmproxy_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.mitmproxy_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 原始数据显示标签页
        self.raw_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.raw_frame, text="原始数据")
        
        self.raw_text = scrolledtext.ScrolledText(self.raw_frame, wrap=tk.WORD)
        self.raw_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def _create_button_section(self, parent):
        """创建按钮区域"""
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=3, column=0, columnspan=3, pady=(0, 10))
        
        # 解析按钮
        parse_btn = ttk.Button(button_frame, text="解析数据", command=self._parse_data)
        parse_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 序列化按钮
        serialize_btn = ttk.Button(button_frame, text="序列化", command=self._serialize_data)
        serialize_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 保存按钮
        save_btn = ttk.Button(button_frame, text="保存结果", command=self._save_result)
        save_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 重置按钮
        reset_btn = ttk.Button(button_frame, text="重置", command=self._reset_all)
        reset_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # 帮助按钮
        help_btn = ttk.Button(button_frame, text="帮助", command=self._show_help)
        help_btn.pack(side=tk.LEFT)
    
    def _clear_input(self):
        """清空输入"""
        self.base64_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)
        self.status_var.set("输入已清空")
    
    def _load_from_file(self):
        """从文件加载数据"""
        file_path = filedialog.askopenfilename(
            title="选择文件",
            filetypes=[("所有文件", "*.*"), ("文本文件", "*.txt"), ("二进制文件", "*.bin")]
        )
        
        if file_path:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                # 更新Base64显示
                encoded = base64.b64encode(data).decode('utf-8')
                self.base64_text.delete(1.0, tk.END)
                self.base64_text.insert(1.0, encoded)
                
                # 更新Hex显示
                hex_data = data.hex()
                self.hex_text.delete(1.0, tk.END)
                self.hex_text.insert(1.0, hex_data)
                
                self.status_var.set(f"已加载文件: {Path(file_path).name}")
            except Exception as e:
                messagebox.showerror("错误", f"加载文件失败: {e}")
    
    def _load_example(self):
        """加载示例数据"""
        # 使用用户提供的示例数据
        example_data = "ChA4koadpQBTPfbv4eIM76pcEAEaFGFwcF9waGVub3R5cGVfc2hhcmVkIJexp8KQMzoCBgRCJwojL2RhdGEvdXNlci8wL2NvbS5nb29nbGUuYW5kcm9pZC5nbXMQIFABWAE="
        
        # 更新显示
        self.base64_text.delete(1.0, tk.END)
        self.base64_text.insert(1.0, example_data)
        
        # 解码并显示hex
        try:
            binary_data = base64.b64decode(example_data)
            hex_data = binary_data.hex()
            self.hex_text.delete(1.0, tk.END)
            self.hex_text.insert(1.0, hex_data)
        except:
            pass
        
        self.status_var.set("已加载示例数据")
    
    def _convert_format(self):
        """转换Base64和Hex格式"""
        try:
            # 获取当前选中的标签页
            current_tab = self.notebook.index(self.notebook.select())
            
            if current_tab == 0:  # Base64标签页
                base64_data = self.base64_text.get(1.0, tk.END).strip()
                if base64_data:
                    # 修复Base64数据
                    fixed_base64 = self._fix_base64_data(base64_data)
                    binary_data = base64.b64decode(fixed_base64)
                    hex_data = binary_data.hex()
                    self.hex_text.delete(1.0, tk.END)
                    self.hex_text.insert(1.0, hex_data)
            else:  # Hex标签页
                hex_data = self.hex_text.get(1.0, tk.END).strip()
                if hex_data:
                    binary_data = bytes.fromhex(hex_data)
                    base64_data = base64.b64encode(binary_data).decode('utf-8')
                    self.base64_text.delete(1.0, tk.END)
                    self.base64_text.insert(1.0, base64_data)
            
            self.status_var.set("格式转换完成")
        except Exception as e:
            messagebox.showerror("错误", f"格式转换失败: {e}")
    
    def _parse_data(self):
        """解析protobuf数据"""
        try:
            # 获取输入数据
            base64_data = self.base64_text.get(1.0, tk.END).strip()
            hex_data = self.hex_text.get(1.0, tk.END).strip()
            
            binary_data = None
            
            if base64_data:
                # 修复Base64数据
                fixed_base64 = self._fix_base64_data(base64_data)
                binary_data = base64.b64decode(fixed_base64)
            elif hex_data:
                binary_data = bytes.fromhex(hex_data)
            else:
                messagebox.showwarning("警告", "请输入数据")
                return
            
            self.original_data = binary_data
            
            # 解析protobuf数据
            self._parse_protobuf_data(binary_data)
            
            self.status_var.set("数据解析完成")
            
        except Exception as e:
            messagebox.showerror("错误", f"解析失败: {e}")
            self.status_var.set("解析失败")
    
    def _parse_protobuf_data(self, data: bytes):
        """解析protobuf数据"""
        try:
            # 使用增强的protobuf解析器
            parsed = self._enhanced_protobuf_parser(data)
            self.parsed_data = parsed
            
            # 显示结构化数据
            self._display_structured_data(parsed)
            
            # 显示JSON格式
            self._display_json(parsed)
            
            # 显示MitmProxy风格格式
            self._display_mitmproxy_style(data)
            
            # 显示原始数据
            self._display_raw_data(data)
            
        except Exception as e:
            # 如果解析失败，显示原始数据
            self._display_raw_data(data)
            messagebox.showerror("错误", f"解析失败: {e}")
    
    def _enhanced_protobuf_parser(self, data: bytes) -> Dict[str, Any]:
        """增强的protobuf解析器，基于CyberChef的逻辑"""
        result = {}
        pos = 0
        
        while pos < len(data):
            if pos >= len(data):
                break
                
            # 读取varint
            field_number, wire_type, pos = self._read_varint_field(data, pos)
            
            if pos >= len(data):
                break
            
            # 根据wire type解析数据
            field_data = self._parse_field_data_enhanced(data, pos, wire_type, field_number)
            if field_data:
                # 处理重复字段：如果字段已存在，创建数组或使用更描述性的名称
                field_key = f"field #{field_number}"
                if field_key in result:
                    # 字段已存在，创建重复字段的标识
                    field_key = f"field #{field_number}_repeat"
                    counter = 1
                    while field_key in result:
                        counter += 1
                        field_key = f"field #{field_number}_repeat_{counter}"
                
                result[field_key] = field_data
                pos = field_data["end_pos"]
            else:
                pos += 1
        
        return result
    
    def _mitmproxy_style_parser(self, data: bytes) -> list:
        """MitmProxy风格的protobuf解析器"""
        result = []
        pos = 0
        field_counts = {}  # 记录每个字段号出现的次数
        
        while pos < len(data):
            if pos >= len(data):
                break
                
            # 读取varint字段头
            field_number, wire_type, pos = self._read_varint_field(data, pos)
            
            if pos >= len(data):
                break
            
            # 记录字段出现次数
            if field_number not in field_counts:
                field_counts[field_number] = 0
            field_counts[field_number] += 1
            
            # 构建当前字段的路径，处理重复字段
            if field_counts[field_number] == 1:
                current_path = str(field_number)
            else:
                # 重复字段添加序号
                current_path = f"{field_number}.{field_counts[field_number]}"
            
            # 根据wire type解析数据
            if wire_type == 0:  # VarInt
                value, pos = self._read_varint(data, pos)
                result.append(f"[uint32]     {current_path:<10} {value}")
            elif wire_type == 1:  # 64-bit
                if pos + 8 <= len(data):
                    import struct
                    value = struct.unpack('<Q', data[pos:pos+8])[0]
                    result.append(f"[uint64]     {current_path:<10} {value}")
                    pos += 8
            elif wire_type == 2:  # Length-delimited
                length, pos = self._read_varint(data, pos)
                if pos + length <= len(data):
                    value = data[pos:pos+length]
                    
                                        # 尝试解析为嵌套消息或字符串
                    nested_result = self._try_parse_nested_message_mitmproxy(value, current_path + ".")
                    if nested_result:
                        result.append(f"[message]    {current_path}")
                        result.extend(nested_result)
                    else:
                        # 尝试解析为字符串
                        try:
                            str_value = value.decode('utf-8')
                            result.append(f"[string]     {current_path:<10} {str_value}")
                        except:
                            # 作为原始字节处理
                            result.append(f"[bytes]      {current_path:<10} {value.hex()}")
                    pos += length
            elif wire_type == 5:  # 32-bit
                if pos + 4 <= len(data):
                    import struct
                    value = struct.unpack('<I', data[pos:pos+4])[0]
                    result.append(f"[fixed32]    {current_path:<10} {value}")
                    pos += 4
        
        return result
    
    def _try_parse_nested_message_mitmproxy(self, data: bytes, path_prefix: str) -> list:
        """MitmProxy风格的嵌套消息解析"""
        try:
            if len(data) < 1:
                return []
            
            pos = 0
            nested_result = []
            valid_fields = 0
            field_counts = {}  # 记录每个字段号出现的次数
            
            # 增加最大字段数限制
            max_fields = 20
            field_count = 0
            
            while pos < len(data) and field_count < max_fields:
                if pos >= len(data):
                    break
                    
                # 读取varint
                field_number, wire_type, pos = self._read_varint_field(data, pos)
                
                if pos >= len(data):
                    break
                
                # 检查字段号是否合理
                if field_number < 1 or field_number > 536870911:
                    break
                
                # 检查wire type是否有效
                if wire_type > 5:
                    break
                
                # 记录字段出现次数
                if field_number not in field_counts:
                    field_counts[field_number] = 0
                field_counts[field_number] += 1
                
                # 构建当前字段的路径，处理重复字段
                if field_counts[field_number] == 1:
                    current_path = f"{path_prefix}{field_number}"
                else:
                    # 重复字段添加序号
                    current_path = f"{path_prefix}{field_number}.{field_counts[field_number]}"
                
                # 根据wire type解析数据
                if wire_type == 0:  # VarInt
                    value, pos = self._read_varint(data, pos)
                    nested_result.append(f"[uint32]     {current_path:<10} {value}")
                    valid_fields += 1
                    field_count += 1
                elif wire_type == 1:  # 64-bit
                    if pos + 8 <= len(data):
                        import struct
                        value = struct.unpack('<Q', data[pos:pos+8])[0]
                        nested_result.append(f"[uint64]     {current_path:<10} {value}")
                        pos += 8
                        valid_fields += 1
                        field_count += 1
                elif wire_type == 2:  # Length-delimited
                    length, pos = self._read_varint(data, pos)
                    if pos + length <= len(data):
                        value = data[pos:pos+length]
                        
                        # 递归尝试解析嵌套消息
                        deeper_nested = self._try_parse_nested_message_mitmproxy(value, current_path + ".")
                        if deeper_nested:
                            nested_result.append(f"[message]    {current_path}")
                            nested_result.extend(deeper_nested)
                        else:
                            # 尝试解析为字符串
                            try:
                                str_value = value.decode('utf-8')
                                nested_result.append(f"[string]     {current_path:<10} {str_value}")
                            except:
                                nested_result.append(f"[bytes]      {current_path:<10} {value.hex()}")
                        pos += length
                        valid_fields += 1
                        field_count += 1
                elif wire_type == 5:  # 32-bit
                    if pos + 4 <= len(data):
                        import struct
                        value = struct.unpack('<I', data[pos:pos+4])[0]
                        nested_result.append(f"[fixed32]    {current_path:<10} {value}")
                        pos += 4
                        valid_fields += 1
                        field_count += 1
            
            # 如果有有效字段，认为是嵌套消息
            if valid_fields >= 1:
                return nested_result
            
        except Exception as e:
            print(f"嵌套消息解析异常: {e}")
        
        return []
    
    def _parse_field_data_enhanced(self, data: bytes, pos: int, wire_type: int, field_number: int) -> Optional[Dict[str, Any]]:
        """增强的字段数据解析"""
        start_pos = pos
        
        try:
            if wire_type == 0:  # Varint
                value, pos = self._read_varint(data, pos)
                return {
                    "type": "VarInt (e.g. int32, bool)",
                    "value": value,
                    "start_pos": start_pos,
                    "end_pos": pos,
                    "raw_data": data[start_pos:pos]
                }
            elif wire_type == 1:  # 64-bit
                if pos + 8 <= len(data):
                    value = struct.unpack('<Q', data[pos:pos+8])[0]
                    return {
                        "type": "64-bit (e.g. fixed64, double)",
                        "value": value,
                        "start_pos": start_pos,
                        "end_pos": pos + 8,
                        "raw_data": data[start_pos:pos+8]
                    }
            elif wire_type == 2:  # Length-delimited
                length, pos = self._read_varint(data, pos)
                if pos + length <= len(data):
                    value = data[pos:pos+length]
                    
                    # 尝试解析为嵌套的protobuf消息
                    nested_result = self._try_parse_nested_message(value)
                    if nested_result:
                        return {
                            "type": "L-delim (e.g. string, message)",
                            "value": nested_result,
                            "start_pos": start_pos,
                            "end_pos": pos + length,
                            "raw_data": data[start_pos:pos+length]
                        }
                    else:
                        # 尝试解析为字符串
                        try:
                            str_value = value.decode('utf-8')
                            return {
                                "type": "L-delim (e.g. string, message)",
                                "value": str_value,
                                "start_pos": start_pos,
                                "end_pos": pos + length,
                                "raw_data": data[start_pos:pos+length]
                            }
                        except:
                            # 作为原始字节处理
                            return {
                                "type": "L-delim (e.g. string, message)",
                                "value": value.hex(),
                                "start_pos": start_pos,
                                "end_pos": pos + length,
                                "raw_data": data[start_pos:pos+length]
                            }
            elif wire_type == 5:  # 32-bit
                if pos + 4 <= len(data):
                    value = struct.unpack('<I', data[pos:pos+4])[0]
                    return {
                        "type": "32-bit (e.g. fixed32, float)",
                        "value": value,
                        "start_pos": start_pos,
                        "end_pos": pos + 4,
                        "raw_data": data[start_pos:pos+4]
                    }
        except:
            pass
        
        return None
    
    def _try_parse_nested_message(self, data: bytes) -> Optional[Dict[str, Any]]:
        """尝试解析嵌套的protobuf消息"""
        try:
            # 检查是否看起来像protobuf数据
            if len(data) < 2:
                return None
            
            # 更严格的检查：确保数据看起来像有效的protobuf
            pos = 0
            nested_result = {}
            valid_fields = 0
            
            # 只解析前几个字段，避免无限递归
            max_fields = 5
            field_count = 0
            
            while pos < len(data) and field_count < max_fields:
                if pos >= len(data):
                    break
                    
                # 读取varint
                field_number, wire_type, pos = self._read_varint_field(data, pos)
                
                if pos >= len(data):
                    break
                
                # 检查字段号是否合理（1-536870911）
                if field_number < 1 or field_number > 536870911:
                    break
                
                # 检查wire type是否有效（0-5）
                if wire_type > 5:
                    break
                
                # 根据wire type解析数据
                field_data = self._parse_field_data_enhanced(data, pos, wire_type, field_number)
                if field_data:
                    nested_result[f"field #{field_number}"] = field_data
                    pos = field_data["end_pos"]
                    field_count += 1
                    valid_fields += 1
                else:
                    break
            
            # 更严格的条件：必须解析出至少2个有效字段，且解析的数据量要合理
            if valid_fields >= 2 and len(nested_result) > 0:
                # 检查解析的数据是否覆盖了大部分原始数据
                total_parsed = sum(field.get("end_pos", 0) - field.get("start_pos", 0) for field in nested_result.values())
                if total_parsed >= len(data) * 0.7:  # 至少解析了70%的数据
                    return nested_result
                
        except:
            pass
        
        return None
    
    def _fix_base64_data(self, data: str) -> str:
        """修复Base64数据"""
        import re
        
        # 移除所有无效字符（只保留Base64有效字符）
        cleaned_data = re.sub(r'[^A-Za-z0-9+/=]', '', data)
        
        # 添加缺失的填充
        while len(cleaned_data) % 4 != 0:
            cleaned_data += '='
        
        return cleaned_data
    
    def _read_varint_field(self, data: bytes, pos: int) -> tuple:
        """读取varint字段号和wire type"""
        if pos >= len(data):
            return 0, 0, pos
        
        byte_val = data[pos]
        field_number = byte_val >> 3
        wire_type = byte_val & 0x07
        pos += 1
        
        return field_number, wire_type, pos
    
    def _read_varint(self, data: bytes, pos: int) -> tuple:
        """读取varint值"""
        result = 0
        shift = 0
        
        while pos < len(data):
            byte_val = data[pos]
            result |= (byte_val & 0x7F) << shift
            pos += 1
            
            if (byte_val & 0x80) == 0:
                break
            shift += 7
        
        return result, pos
    
    def _display_structured_data(self, data: Dict[str, Any]):
        """显示结构化数据"""
        # 清空字段列表
        self.field_listbox.delete(0, tk.END)
        
        # 添加字段到列表
        for key, value in data.items():
            if isinstance(value, dict):
                field_type = value.get('type', 'unknown')
                field_value = value.get('value', '?')
                
                # 处理嵌套消息
                if isinstance(field_value, dict):
                    field_info = f"{key}: {field_type} (嵌套消息)"
                else:
                    field_info = f"{key}: {field_type} = {field_value}"
                
                self.field_listbox.insert(tk.END, field_info)
        
        # 清空详情显示
        self.field_details.delete(1.0, tk.END)
        self.edit_var.set("")
    
    def _update_field_list_display(self):
        """更新字段列表显示（保持选择状态）"""
        # 获取当前选择
        current_selection = self.field_listbox.curselection()
        
        # 清空字段列表
        self.field_listbox.delete(0, tk.END)
        
        # 重新添加字段到列表
        for key, value in self.parsed_data.items():
            if isinstance(value, dict):
                field_type = value.get('type', 'unknown')
                field_value = value.get('value', '?')
                
                # 处理嵌套消息
                if isinstance(field_value, dict):
                    field_info = f"{key}: {field_type} (嵌套消息)"
                else:
                    field_info = f"{key}: {field_type} = {field_value}"
                
                self.field_listbox.insert(tk.END, field_info)
        
        # 恢复选择状态
        if current_selection:
            self.field_listbox.selection_set(current_selection[0])
    
    def _make_serializable(self, data: Any) -> Any:
        """将数据转换为可JSON序列化的格式"""
        if isinstance(data, dict):
            result = {}
            for key, value in data.items():
                result[key] = self._make_serializable(value)
            return result
        elif isinstance(data, list):
            return [self._make_serializable(item) for item in data]
        elif isinstance(data, bytes):
            # 将bytes转换为十六进制字符串
            return data.hex()
        elif isinstance(data, (int, float, str, bool)) or data is None:
            return data
        else:
            # 其他类型转换为字符串
            return str(data)
    
    def _display_json(self, data: Dict[str, Any]):
        """显示JSON格式"""
        self.json_text.delete(1.0, tk.END)
        
        # 创建可序列化的数据副本
        serializable_data = self._make_serializable(data)
        
        json_str = json.dumps(serializable_data, indent=2, ensure_ascii=False)
        self.json_text.insert(1.0, json_str)
    
    def _display_mitmproxy_style(self, data: bytes):
        """显示MitmProxy风格格式"""
        self.mitmproxy_text.delete(1.0, tk.END)
        
        try:
            # 使用MitmProxy风格解析器
            mitmproxy_result = self._mitmproxy_style_parser(data)
            
            # 显示结果
            for item in mitmproxy_result:
                self.mitmproxy_text.insert(tk.END, item + "\n")
                
        except Exception as e:
            self.mitmproxy_text.insert(1.0, f"MitmProxy风格解析失败: {e}")
    
    def _display_raw_data(self, data: bytes):
        """显示原始数据"""
        self.raw_text.delete(1.0, tk.END)
        
        # 显示基本信息
        info = f"数据长度: {len(data)} 字节\n"
        info += f"Base64: {base64.b64encode(data).decode('utf-8')}\n"
        info += f"Hex: {data.hex()}\n\n"
        
        # 显示十六进制转储
        info += "十六进制转储:\n"
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            info += f"{i:08x}: {hex_str:<48} |{ascii_str}|\n"
        
        self.raw_text.insert(1.0, info)
    
    def _on_field_select(self, event):
        """字段选择事件"""
        selection = self.field_listbox.curselection()
        if not selection:
            return
        
        # 获取选中的字段
        field_index = selection[0]
        field_keys = list(self.parsed_data.keys())
        if field_index < len(field_keys):
            field_key = field_keys[field_index]
            field_data = self.parsed_data[field_key]
            
            # 显示字段详情
            self._show_field_details(field_data)
    
    def _show_field_details(self, field_data: Dict[str, Any]):
        """显示字段详情"""
        self.field_details.delete(1.0, tk.END)
        
        details = f"字段类型: {field_data.get('type', 'N/A')}\n"
        details += f"当前值: {field_data.get('value', 'N/A')}\n"
        details += f"起始位置: {field_data.get('start_pos', 'N/A')}\n"
        details += f"结束位置: {field_data.get('end_pos', 'N/A')}\n"
        details += f"原始数据: {field_data.get('raw_data', b'').hex()}\n"
        
        self.field_details.insert(1.0, details)
        
        # 设置编辑框的当前值
        current_value = field_data.get('value', '')
        if isinstance(current_value, dict):
            self.edit_var.set("(嵌套消息)")
        else:
            self.edit_var.set(str(current_value))
    
    def _update_field_value(self):
        """更新字段值"""
        selection = self.field_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个字段")
            return
        
        new_value = self.edit_var.get()
        if not new_value:
            messagebox.showwarning("警告", "请输入新值")
            return
        
        # 获取选中的字段
        field_index = selection[0]
        field_keys = list(self.parsed_data.keys())
        if field_index < len(field_keys):
            field_key = field_keys[field_index]
            field_data = self.parsed_data[field_key]
            
            # 更新值
            try:
                # 根据类型转换值
                field_type = field_data.get('type', '')
                if 'VarInt' in field_type:
                    field_data['value'] = int(new_value)
                elif '64-bit' in field_type:
                    field_data['value'] = int(new_value)
                elif '32-bit' in field_type:
                    field_data['value'] = int(new_value)
                elif 'L-delim' in field_type:
                    field_data['value'] = new_value
                else:
                    field_data['value'] = new_value
                
                # 更新JSON显示
                self._display_json(self.parsed_data)
                
                # 更新字段列表显示（保持选择状态）
                self._update_field_list_display()
                
                # 重新选择字段
                self.field_listbox.selection_set(field_index)
                self._show_field_details(field_data)
                
                self.status_var.set("字段值已更新")
                
            except Exception as e:
                messagebox.showerror("错误", f"更新值失败: {e}")
    
    def _reset_field_value(self):
        """重置字段值"""
        selection = self.field_listbox.curselection()
        if not selection:
            return
        
        # 获取选中的字段
        field_index = selection[0]
        field_keys = list(self.parsed_data.keys())
        if field_index < len(field_keys):
            field_key = field_keys[field_index]
            field_data = self.parsed_data[field_key]
            
            # 重置为原始值
            original_value = self._get_original_field_value(field_data)
            self.edit_var.set(str(original_value))
    
    def _get_original_field_value(self, field_data: Dict[str, Any]) -> Any:
        """获取字段的原始值"""
        # 这里可以从原始数据中重新解析
        return field_data.get('value', '')
    
    def _serialize_data(self):
        """序列化数据"""
        try:
            if not self.parsed_data:
                messagebox.showwarning("警告", "没有可序列化的数据，请先解析数据")
                return
            
            # 序列化整个解析后的数据结构
            serialized = self._serialize_protobuf_data(self.parsed_data)
            
            if not serialized:
                messagebox.showwarning("警告", "序列化结果为空")
                return
            
            # 更新显示
            encoded = base64.b64encode(serialized).decode('utf-8')
            self.base64_text.delete(1.0, tk.END)
            self.base64_text.insert(1.0, encoded)
            
            hex_data = serialized.hex()
            self.hex_text.delete(1.0, tk.END)
            self.hex_text.insert(1.0, hex_data)
            
            # 显示结果
            self._show_serialized_result(encoded, hex_data)
            
            self.status_var.set(f"数据序列化完成，生成 {len(serialized)} 字节")
            
        except Exception as e:
            messagebox.showerror("错误", f"序列化失败: {e}")
            self.status_var.set("序列化失败")
    
    def _serialize_protobuf_data(self, data: Dict[str, Any]) -> bytes:
        """序列化protobuf数据"""
        result = bytearray()
        
        # 按字段号排序，确保序列化顺序一致
        sorted_fields = sorted(data.items(), key=lambda x: int(x[0].split("#")[1]) if x[0].startswith("field #") else 0)
        
        for key, value in sorted_fields:
            if key.startswith("field #"):
                field_number = int(key.split("#")[1])
                field_type = value.get("type", "")
                field_value = value.get("value")
                
                # 跳过空值
                if field_value is None:
                    continue
                
                # 根据类型确定wire type
                if 'VarInt' in field_type:
                    wire_type = 0
                elif '64-bit' in field_type:
                    wire_type = 1
                elif 'L-delim' in field_type:
                    wire_type = 2
                elif '32-bit' in field_type:
                    wire_type = 5
                else:
                    continue
                
                # 编码字段号和wire type
                field_header = (field_number << 3) | wire_type
                result.extend(self._encode_varint(field_header))
                
                # 编码值
                if wire_type == 0:  # Varint
                    result.extend(self._encode_varint(int(field_value)))
                elif wire_type == 1:  # 64-bit
                    result.extend(struct.pack('<Q', int(field_value)))
                elif wire_type == 2:  # Length-delimited
                    if isinstance(field_value, dict):
                        # 嵌套消息
                        nested_data = self._serialize_protobuf_data(field_value)
                        result.extend(self._encode_varint(len(nested_data)))
                        result.extend(nested_data)
                    else:
                        # 字符串或字节
                        if isinstance(field_value, str):
                            # 检查是否是hex字符串
                            if self._is_hex_string(field_value):
                                str_bytes = bytes.fromhex(field_value)
                            else:
                                str_bytes = field_value.encode('utf-8')
                        else:
                            str_bytes = bytes(field_value) if hasattr(field_value, '__iter__') else str(field_value).encode('utf-8')
                        result.extend(self._encode_varint(len(str_bytes)))
                        result.extend(str_bytes)
                elif wire_type == 5:  # 32-bit
                    result.extend(struct.pack('<I', int(field_value)))
        
        return bytes(result)
    
    def _encode_varint(self, value: int) -> bytes:
        """编码varint"""
        result = bytearray()
        
        while value >= 0x80:
            result.append((value & 0xFF) | 0x80)
            value >>= 7
        
        result.append(value & 0xFF)
        return bytes(result)
    
    def _is_hex_string(self, s: str) -> bool:
        """检查字符串是否为有效的十六进制字符串"""
        try:
            int(s, 16)
            return len(s) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in s)
        except ValueError:
            return False
    
    def _show_serialized_result(self, base64_data: str, hex_data: str):
        """显示序列化结果"""
        # 创建新窗口显示结果
        result_window = tk.Toplevel(self.root)
        result_window.title("序列化结果")
        result_window.geometry("700x500")
        
        # 标题
        ttk.Label(result_window, text="序列化结果", 
                 font=("Arial", 12, "bold")).pack(pady=10)
        
        # 创建Notebook
        result_notebook = ttk.Notebook(result_window)
        result_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Base64标签页
        base64_frame = ttk.Frame(result_notebook)
        result_notebook.add(base64_frame, text="Base64")
        
        base64_text = scrolledtext.ScrolledText(base64_frame, wrap=tk.WORD)
        base64_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        base64_text.insert(1.0, base64_data)
        
        # Hex标签页
        hex_frame = ttk.Frame(result_notebook)
        result_notebook.add(hex_frame, text="Hex")
        
        hex_text = scrolledtext.ScrolledText(hex_frame, wrap=tk.WORD)
        hex_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        hex_text.insert(1.0, hex_data)
        
        # 按钮框架
        btn_frame = ttk.Frame(result_window)
        btn_frame.pack(pady=10)
        
        def copy_base64():
            result_window.clipboard_clear()
            result_window.clipboard_append(base64_data)
            messagebox.showinfo("成功", "Base64数据已复制到剪贴板")
        
        def copy_hex():
            result_window.clipboard_clear()
            result_window.clipboard_append(hex_data)
            messagebox.showinfo("成功", "Hex数据已复制到剪贴板")
        
        def save_to_file():
            file_path = filedialog.asksaveasfilename(
                title="保存文件",
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Base64:\n{base64_data}\n\nHex:\n{hex_data}")
                messagebox.showinfo("成功", f"已保存到: {file_path}")
        
        ttk.Button(btn_frame, text="复制Base64", command=copy_base64).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="复制Hex", command=copy_hex).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="保存到文件", command=save_to_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="关闭", command=result_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def _save_result(self):
        """保存结果"""
        if not self.parsed_data:
            messagebox.showwarning("警告", "没有可保存的数据")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="保存解析结果",
            defaultextension=".json",
            filetypes=[("JSON文件", "*.json"), ("所有文件", "*.*")]
        )
        
        if file_path:
            try:
                # 创建可序列化的数据副本
                serializable_data = self._make_serializable(self.parsed_data)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(serializable_data, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("成功", f"结果已保存到: {file_path}")
            except Exception as e:
                messagebox.showerror("错误", f"保存失败: {e}")
    
    def _reset_all(self):
        """重置所有数据"""
        self._clear_input()
        self.field_listbox.delete(0, tk.END)
        self.field_details.delete(1.0, tk.END)
        self.json_text.delete(1.0, tk.END)
        self.mitmproxy_text.delete(1.0, tk.END)
        self.raw_text.delete(1.0, tk.END)
        self.edit_var.set("")
        
        self.parsed_data = {}
        self.original_data = b""
        self.status_var.set("已重置")
    
    def _show_help(self):
        """显示帮助信息"""
        help_text = """
增强版Protobuf数据编辑器使用说明：

1. 输入数据：
   - 在Base64标签页输入base64编码的数据
   - 在Hex标签页输入十六进制数据
   - 使用"Base64↔Hex"按钮转换格式

2. 解析数据：
   - 点击"解析数据"按钮解析protobuf数据
   - 在"结构化显示"标签页查看解析结果
   - 在"MitmProxy风格"标签页查看类似MitmProxy的层次化显示
   - 选择字段查看详细信息

3. 编辑数据：
   - 在字段列表中选择要编辑的字段
   - 在编辑框中输入新值
   - 点击"更新值"按钮保存修改

4. 序列化：
   - 点击"序列化"按钮生成新的protobuf数据
   - 结果会显示在弹出窗口中

5. 保存结果：
   - 可以保存解析结果为JSON文件
   - 可以保存序列化结果为文本文件

支持的字段类型：
- VarInt: 变长整数 (int32, bool等)
- 64-bit: 64位整数 (fixed64, double等)
- 32-bit: 32位整数 (fixed32, float等)
- L-delim: 长度分隔 (string, message等)

特性：
- 支持嵌套protobuf消息解析
- 更准确的字段类型识别
- 基于CyberChef的解析逻辑
        """
        
        help_window = tk.Toplevel(self.root)
        help_window.title("帮助")
        help_window.geometry("600x500")
        
        text_widget = scrolledtext.ScrolledText(help_window, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(1.0, help_text)
        text_widget.config(state=tk.DISABLED)
        
        ttk.Button(help_window, text="关闭", command=help_window.destroy).pack(pady=10)
    
    def run(self):
        """运行应用"""
        self.root.mainloop()

def main():
    """主函数"""
    app = EnhancedProtobufEditor()
    app.run()

if __name__ == "__main__":
    main()
