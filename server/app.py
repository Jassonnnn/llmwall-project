# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, stream_with_context, Response
import json
import codecs

# 从 'checkers' 包中导入函数
from checkers.input_checker import input_check
from checkers.output_checker import output_check
from checkers.stream_checker import stream_output_check

# 初始化 Flask 应用
app = Flask(__name__)
# 确保中文字符能正常显示
app.config['JSON_AS_ASCII'] = False

# --- API 端点定义 ---

@app.route('/check_input', methods=['POST'])
def check_input_endpoint():
    """
    输入检查端点。
    """
    try:
        data = request.get_json()
        required_fields = ['text', 'checks', 'params']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"status": 400, "error": f"请求格式错误，缺少必要字段: {required_fields}"}), 400

        text_to_check = data['text']
        checks = data['checks']
        params = data['params']

        # [MODIFIED] 接收包含处理后文本在内的三个返回值
        is_problematic, message, processed_text = input_check(text_to_check, checks, params)

        if is_problematic:
            return jsonify({"status": 403, "error": message}), 403
        else:
            # [MODIFIED] 在成功响应中加入处理后的文本
            return jsonify({"status": 200, "message": processed_text}), 200

    except Exception as e:
        return jsonify({"status": 500, "error": f"服务器内部错误: {str(e)}"}), 500


@app.route('/check_output', methods=['POST'])
def check_output_endpoint():
    """
    输出审核端点。
    """
    try:
        data = request.get_json()
        required_fields = ['text_to_check', 'checks', 'params']
        if not data or not all(field in data for field in required_fields):
            return jsonify({"status": 400, "error": f"请求格式错误，缺少必要字段: {required_fields}"}), 400

        text_to_check = data['text']
        checks = data['checks']
        params = data['params']
        
        # [MODIFIED] 接收包含处理后文本在内的三个返回值
        is_problematic, message, processed_text = input_check(text_to_check, checks, params)

        if is_problematic:
            return jsonify({"status": 403, "error": message}), 403
        else:
            # [MODIFIED] 在成功响应中加入处理后的文本
            return jsonify({"status": 200, "message": processed_text}), 200

    except Exception as e:
        return jsonify({"status": 500, "error": f"服务器内部错误: {str(e)}"}), 500

@app.route('/check_output_stream', methods=['POST'])
def check_output_multipart_endpoint():
    """
    一个使用 multipart/form-data 处理流式请求的端点。
    它接收一个包含两部分的请求:
    1. 'config': 一个包含 checks 和 params 的 JSON 文件部分。
    2. 'stream': 一个包含原始文本流的文件部分。
    """
    try:
        # 检查请求是否为 multipart 类型
        if not request.mimetype.startswith('multipart/form-data'):
            return jsonify({"status": 415, "error": "请求必须是 multipart/form-data 类型"}), 415

        # --- 1. 解析配置部分 (Part 1: Config) ---
        config_part = request.files.get('config')
        if not config_part:
            return jsonify({"status": 400, "error": "请求中缺少名为 'config' 的部分"}), 400
        
        try:
            config_data = json.load(config_part)
            checks = config_data.get('checks', [])
            params = config_data.get('params', {})
        except (json.JSONDecodeError, TypeError):
            return jsonify({"status": 400, "error": "'config' 部分包含无效的 JSON"}), 400
        
        print(f"接收到配置: checks={checks}, params={params}")

        # --- 2. 处理流式部分 (Part 2: Stream) ---
        stream_part = request.files.get('stream')
        if not stream_part:
            return jsonify({"status": 400, "error": "请求中缺少名为 'stream' 的部分"}), 400
        
        print("正在接收和处理流式输入...")

        # 创建一个解码器生成器，直接处理输入的请求流
        def decode_stream(input_stream):
            # stream_part.stream 是一个字节流，我们需要将其解码为文本流
            decoder = codecs.getincrementaldecoder('utf-8')()
            # 以小块（chunk）为单位读取，以确保流式处理
            for byte_chunk in iter(lambda: input_stream.read(4096), b''):
                yield decoder.decode(byte_chunk)
            final_chunk = decoder.decode(b'', final=True)
            if final_chunk:
                yield final_chunk

        # 从上传的文件部分获取原始字节流
        raw_byte_stream = stream_part.stream
        
        # 将字节流转换为文本流
        raw_text_stream = decode_stream(raw_byte_stream)
        
        # 将原始文本流传入您的检查器，得到一个安全的、处理后的流
        processed_stream_generator = stream_output_check(raw_text_stream, checks, params)
        
        # 将处理后的安全流返回给调用方
        return Response(stream_with_context(processed_stream_generator), mimetype='text/plain; charset=utf-8')

    except Exception as e:
        # 在生产环境中，这里的日志记录应该更详细
        print(f"服务器内部错误: {e}")
        return jsonify({"status": 500, "error": f"服务器内部错误: {str(e)}"}), 500

# --- 启动服务器 ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
