#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
import time
import logging
from base64 import b64decode
from hashlib import sha1
from math import ceil
from mimetypes import guess_type
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any
from concurrent.futures import ThreadPoolExecutor
from functools import wraps
from http.cookiejar import MozillaCookieJar
import requests
import uuid
import argparse

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('acfun')

# 定义装饰器，用于处理请求异常和重试
def retry(max_retries=3, retry_delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(1, max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    logger.warning(f"尝试 {attempt}/{max_retries} 失败: {e}")
                    if attempt < max_retries:
                        time.sleep(retry_delay)
            logger.error(f"所有重试都失败: {last_exception}")
            raise last_exception
        return wrapper
    return decorator

class AuthenticationError(Exception):
    """自定义认证错误异常"""
    pass

class AcFun:
    """AcFun视频上传客户端"""
    
    # API 端点
    ENDPOINTS = {
        'login': "https://id.app.acfun.cn/rest/web/login/signin",
        'token': "https://member.acfun.cn/video/api/getKSCloudToken",
        'fragment': "https://upload.kuaishouzt.com/api/upload/fragment",
        'complete': "https://upload.kuaishouzt.com/api/upload/complete",
        'finish': "https://member.acfun.cn/video/api/uploadFinish",
        'create_video': "https://member.acfun.cn/video/api/createVideo",
        'create_douga': "https://member.acfun.cn/video/api/createDouga",
        'qiniu_token': "https://member.acfun.cn/common/api/getQiniuToken",
        'cover_url': "https://member.acfun.cn/common/api/getUrlAfterUpload",
        'image_url': "https://imgs.aixifan.com/"
    }
    
    # 默认请求头
    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Origin": "https://member.acfun.cn",
        "Referer": "https://member.acfun.cn/"
    }
    
    def __init__(self, cookie_file: Optional[str] = None):
        """
        初始化AcFun客户端
        
        Args:
            cookie_file: Cookie文件路径，默认为config目录下的acfun_cookies.txt
        """
        self.session = requests.session()
        self.session.headers.update(self.DEFAULT_HEADERS)
        
        # 配置Cookie文件
        if cookie_file is None:
            # 当 acfun.py 在根目录时，Path(__file__).parent 即为项目根目录
            base_dir = Path(__file__).parent 
            self.cookie_file = base_dir / 'config' / 'acfun_cookies.txt'
        else:
            self.cookie_file = Path(cookie_file)
            
        # 确保config目录存在
        self.cookie_file.parent.mkdir(exist_ok=True)
        
        # 加载Cookie
        self._load_cookies()
    

    
    def _load_cookies(self) -> bool:
        """从文件加载cookies到session"""
        if not self.cookie_file.exists():
            logger.info(f"Cookie文件不存在: {self.cookie_file}")
            return False
            
        try:
            cookie_jar = MozillaCookieJar(self.cookie_file)
            cookie_jar.load(ignore_discard=True, ignore_expires=True)
            
            # 将cookie_jar中的cookie添加到session中
            self.session.cookies.update(cookie_jar)
            
            # 尝试验证cookie是否有效 (简单检查是否有关键cookie)
            required_cookies = ['auth_key', 'acPasstoken', 'ac_username'] # 添加ac_username检查
            
            # 从jar中提取cookie名称进行检查
            loaded_cookie_names = {c.name for c in cookie_jar}
            has_required = all(name in loaded_cookie_names for name in required_cookies)
            
            if has_required:
                # 可以考虑在这里添加一个轻量级的API调用来真正验证cookie的有效性
                # 例如，尝试获取用户信息。如果失败，则认为cookie无效。
                # logger.info("尝试验证Cookie有效性...")
                # if not self.is_cookie_valid(): # 假设有这样一个方法
                #     logger.warning("Cookie文件中的认证信息无效或已过期。")
                #     self.cookie_file.unlink(missing_ok=True) # 删除无效的cookie文件
                #     return False
                logger.info("成功从文件加载Cookie")
                return True
            else:
                missing = [name for name in required_cookies if name not in loaded_cookie_names]
                logger.warning(f"加载的Cookie缺少关键值: {missing}，可能已过期或不完整。")
                self.cookie_file.unlink(missing_ok=True) # 删除不完整的cookie文件
                return False
                
        except Exception as e:
            logger.error(f"加载Cookie文件失败: {e}")
            if self.cookie_file.exists(): # 如果文件存在但加载失败，也删除它
                 self.cookie_file.unlink(missing_ok=True)
            return False
    
    def _save_cookies(self):
        """将当前session的cookies保存到文件"""
        try:
            cookie_jar = MozillaCookieJar(self.cookie_file)
            
            # 首先加载现有cookie (如果存在)
            if self.cookie_file.exists():
                cookie_jar.load(ignore_discard=True, ignore_expires=True)
            
            # 更新cookie_jar
            for cookie in self.session.cookies:
                cookie_jar.set_cookie(cookie)
            
            # 保存到文件
            cookie_jar.save(ignore_discard=True, ignore_expires=True)
            logger.info(f"已保存Cookie到: {self.cookie_file}")
            
        except Exception as e:
            logger.error(f"保存Cookie失败: {e}")
    
    @staticmethod
    def calc_sha1(data: bytes) -> str:
        """计算SHA1哈希值"""
        sha1_obj = sha1()
        sha1_obj.update(data)
        return sha1_obj.hexdigest()
    
    @retry(max_retries=3)
    def login(self, username: str, password: str) -> bool:
        """
        登录AcFun账号
        
        Args:
            username: 用户名
            password: 密码
            
        Returns:
            登录是否成功
        """
        # 登录前清空现有session的cookies，确保不会携带旧的或无效的cookie
        self.session.cookies.clear()
        
        login_data = {
            'username': username,
            'password': password,
            'key': '',
            'captcha': ''
        }
        
        response = self.session.post(
            url=self.ENDPOINTS['login'],
            data=login_data
        )
        
        try:
            result = response.json()
        except json.JSONDecodeError:
            logger.error(f"登录响应非JSON格式: {response.text}")
            return False

        if result.get('result') == 0:
            logger.info('登录成功')
            self._save_cookies()
            return True
        else:
            error_msg = result.get('error_msg', result.get('err_msg', '未知错误')) # 兼容errMsg和error_msg
            logger.error(f"登录失败: {error_msg} (响应: {result})")
            return False

    @retry(max_retries=3) # 保持重试，但对于认证错误需要特殊处理
    def get_token(self, filename: str, filesize: int) -> Tuple[int, str, int]:
        """
        获取上传Token
        
        Args:
            filename: 文件名
            filesize: 文件大小(字节)
            
        Returns:
            (taskId, token, partSize)
        """
        response = self.session.post(
            url=self.ENDPOINTS['token'],
            data={
                "fileName": filename,
                "size": filesize,
                "template": "1"
            }
        )
        
        try:
            response_json = response.json()
        except json.JSONDecodeError:
            # 如果响应不是JSON，并且状态码是401，则认为是认证失败
            if response.status_code == 401:
                logger.error(f"获取上传Token认证失败 (401)，响应非JSON: {response.text}")
                raise AuthenticationError(f"认证失败 (401)，请重新登录。响应: {response.text}")
            logger.error(f"获取上传Token响应非JSON格式: {response.text}")
            raise Exception(f"获取上传Token响应非JSON格式: {response.text}")

        # 检查是否是AcFun返回的特定错误结构 (errMsg, isError)
        if response_json.get("isError") is True and "errMsg" in response_json:
            error_message_detail = response_json.get("errMsg", {}).get("message", "")
            if response.status_code == 401 or "401" in error_message_detail:
                logger.error(f"获取上传Token认证失败 (401): {response_json.get('errMsg')}")
                # 在这里抛出AuthenticationError，以便上层可以捕获并处理（例如，删除旧cookie，提示重新登录）
                # 不应在此处删除cookie文件，让调用者决定
                raise AuthenticationError(f"认证失败 (401)，请重新登录。错误: {response_json.get('errMsg')}")
            else: # 其他isError情况
                err_msg_content = response_json.get('errMsg', '未知错误详情')
                logger.error(f"获取上传Token API返回错误: {err_msg_content}")
                raise Exception(f"获取上传Token API返回错误: {err_msg_content}")

        # 检查正常的响应结构
        if response_json.get('result') != 0:
            error_detail = f"响应: {response_json}"
            if "result" not in response_json:
                error_msg = f"'result'键缺失. {error_detail}"
            else: # 'result' is present but not 0
                error_msg = response_json.get('error_msg', f"result为{response_json.get('result')}. {error_detail}")

            logger.error(f"获取上传Token失败: {error_msg}")
            raise Exception(f"获取上传Token失败: {error_msg}")
            
        # Ensure all expected keys are present before returning
        if not all(k in response_json for k in ["taskId", "token"]) or \
           not isinstance(response_json.get("uploadConfig"), dict) or \
           "partSize" not in response_json.get("uploadConfig", {}):
            error_detail = f"响应: {response_json}"
            error_msg = f"响应结构不完整. {error_detail}"
            logger.error(f"获取上传Token失败: {error_msg}")
            raise Exception(f"获取上传Token失败: {error_msg}")

        return response_json["taskId"], response_json["token"], response_json["uploadConfig"]["partSize"]

    @retry(max_retries=3)
    def upload_chunk(self, block: bytes, fragment_id: int, upload_token: str) -> bool:
        """
        上传单个分块
        
        Args:
            block: 分块数据
            fragment_id: 分块ID
            upload_token: 上传Token
            
        Returns:
            上传是否成功
        """
        headers = {
            **self.DEFAULT_HEADERS,
            "Content-Type": "application/octet-stream",
        }
        
        response = self.session.post(
            url=self.ENDPOINTS['fragment'],
            params={
                "fragment_id": fragment_id,
                "upload_token": upload_token
            },
            data=block,
            headers=headers,
            timeout=60  # 增加超时时间
        ).json()
        
        if response.get("result") == 1:
            logger.info(f"分块 {fragment_id+1} 上传成功")
            return True
        else:
            error_msg = response.get('error_msg', '未知错误')
            logger.error(f"分块 {fragment_id+1} 上传失败: {error_msg}")
            raise Exception(f"分块上传失败: {error_msg}")

    @retry(max_retries=3)
    def complete(self, fragment_count: int, upload_token: str) -> bool:
        """
        完成上传
        
        Args:
            fragment_count: 分块总数
            upload_token: 上传Token
            
        Returns:
            是否成功
        """
        headers = {
            **self.DEFAULT_HEADERS,
            "Content-Length": "0",
        }
        
        response = self.session.post(
            url=self.ENDPOINTS['complete'],
            params={
                "fragment_count": fragment_count,
                "upload_token": upload_token
            },
            headers=headers,
            timeout=60
        ).json()
        
        if response.get("result") == 1:
            logger.info("完成上传操作成功")
            return True
        else:
            error_msg = response.get('error_msg', '未知错误')
            logger.error(f"完成上传操作失败: {error_msg}")
            raise Exception(f"完成上传操作失败: {error_msg}")
    
    @retry(max_retries=3)
    def upload_finish(self, task_id: int) -> bool:
        """
        通知服务器上传已完成
        
        Args:
            task_id: 任务ID
            
        Returns:
            是否成功
        """
        response = self.session.post(
            url=self.ENDPOINTS['finish'],
            data={"taskId": task_id}
        ).json()
        
        if response.get("result") == 0:
            logger.info("上传完成通知成功")
            return True
        else:
            error_msg = response.get('error_msg', '未知错误')
            logger.warning(f"上传完成通知失败: {error_msg}")
            return False

    @retry(max_retries=3)
    def create_video(self, video_key: int, filename: str) -> int:
        """
        创建视频
        
        Args:
            video_key: 视频key(任务ID)
            filename: 文件名
            
        Returns:
            视频ID
        """
        headers = {
            **self.DEFAULT_HEADERS,
            "origin": "https://member.acfun.cn",
            "referer": "https://member.acfun.cn/upload-video"
        }
        
        response = self.session.post(
            url=self.ENDPOINTS['create_video'],
            data={
                "videoKey": video_key,
                "fileName": filename,
                "vodType": "ksCloud"
            },
            headers=headers
        ).json()
        
        if response.get("result") == 0 and "videoId" in response:
            logger.info(f"创建视频成功，视频ID: {response['videoId']}")
            # 完成上传
            self.upload_finish(video_key)
            return response["videoId"]
        else:
            error_msg = response.get('error_msg', '未知错误')
            logger.error(f"创建视频失败: {error_msg}")
            raise Exception(f"创建视频失败: {error_msg}")

    @retry(max_retries=3)
    def get_qiniu_token(self, filename: str) -> str:
        """
        获取七牛云上传Token
        
        Args:
            filename: 文件名
            
        Returns:
            七牛云Token
        """
        response_json = self.session.post(
            url=self.ENDPOINTS['qiniu_token'],
            data={"fileName": filename + ".jpeg"}
        ).json()
        
        if response_json.get('result') == 0 and \
           'info' in response_json and \
           isinstance(response_json.get('info'), dict) and \
           'token' in response_json.get('info', {}):
            return response_json["info"]["token"]
        else:
            error_detail = f"响应: {response_json}"
            if "result" not in response_json:
                error_msg = f"'result'键缺失. {error_detail}"
            elif response_json.get('result') == 0 and \
                 (not isinstance(response_json.get('info'), dict) or \
                  'token' not in response_json.get('info', {})):
                error_msg = f"result为0但info或token结构不符. {error_detail}"
            else:
                error_msg = response_json.get('error_msg', f"未知错误或结构不符. {error_detail}")

            logger.error(f"获取七牛云Token失败: {error_msg}")
            raise Exception(f"获取七牛云Token失败: {error_msg}")

    def upload_cover(self, image_path: str) -> str:
        """
        上传封面图片
        
        Args:
            image_path: 图片路径
            
        Returns:
            图片URL
        """
        # 读取图片文件
        with open(image_path, "rb") as f:
            file_data = f.read()
        
        # 生成文件名 (Pythonic way)
        filename = f"o_{int(time.time() * 1000):x}_{uuid.uuid4().hex[:10]}"
        
        # 获取七牛云上传Token
        token = self.get_qiniu_token(filename)
        
        # 上传图片
        self.upload_chunk(file_data, 0, token)
        
        # 完成上传
        self.complete(1, token)
        
        # 获取图片URL
        response_json = self.session.post(
            url=self.ENDPOINTS['cover_url'],
            data={
                "bizFlag": "web-douga-cover",
                "token": token
            }
        ).json()
        
        if response_json.get('result') == 0 and 'url' in response_json:
            logger.info(f"封面上传成功: {response_json['url']}")
            return response_json["url"]
        else:
            error_detail = f"响应: {response_json}"
            if "result" not in response_json:
                error_msg = f"'result'键缺失. {error_detail}"
            elif 'url' not in response_json and response_json.get("result") == 0:
                error_msg = f"'url'键缺失但result为0. {error_detail}"
            else:
                error_msg = response_json.get('error_msg', f"未知错误. {error_detail}")
            
            logger.error(f"获取封面URL失败: {error_msg}")
            raise Exception(f"获取封面URL失败: {error_msg}")

    def upload_video(self, file_path: str, max_workers: int = 5) -> Tuple[int, str]:
        """
        使用多线程上传视频文件
        
        Args:
            file_path: 视频文件路径
            max_workers: 最大线程数
            
        Returns:
            (任务ID, 文件名)
        """
        file_path = Path(file_path)
        file_name = file_path.name
        file_size = file_path.stat().st_size
        
        try:
            # 获取上传Token
            task_id, token, part_size = self.get_token(file_name, file_size)
        except AuthenticationError: # 捕获认证错误
            logger.warning("获取视频上传Token时认证失败，尝试清除Cookie并重新登录...")
            if self.cookie_file.exists():
                self.cookie_file.unlink() # 删除无效的cookie文件
            logger.info("Cookie文件已删除。请提供用户名和密码进行登录。")
            # 这里可以根据实际需求决定是直接抛出让外部处理，还是尝试在此处重新登录
            # 为简单起见，先抛出，让test.py中的逻辑处理重新登录
            raise # 重新抛出AuthenticationError，让create_douga处理或test.py处理

        # 计算分块数量
        fragment_count = ceil(file_size / part_size)
        logger.info(f"{file_name} 开始上传, 文件大小: {file_size/1024/1024:.2f}MB, 共{fragment_count}个分块")
        
        # 使用线程池进行并行上传
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            
            with open(file_path, "rb") as f:
                for fragment_id in range(fragment_count):
                    chunk_data = f.read(part_size)
                    if not chunk_data:
                        break
                    
                    # 提交上传任务到线程池
                    future = executor.submit(self.upload_chunk, chunk_data, fragment_id, token)
                    futures.append(future)
            
            # 等待所有任务完成
            for future in futures:
                future.result()  # 这会抛出任何在线程中发生的异常
        
        # 完成上传
        self.complete(fragment_count, token)
        logger.info(f"{file_name} 上传完成")
        
        return task_id, file_name

    @retry(max_retries=1) # 对于顶层操作，认证失败不应多次重试整个流程
    def create_douga(
        self,
        file_path: str,              # 视频文件路径
        title: str,                  # 稿件标题
        channel_id: int,             # 频道ID
        cover: str,                  # 视频封面图片路径
        desc: str = "",              # 稿件简介
        tags: List[str] = [],        # 稿件标签列表
        creation_type: int = 1,      # 1=转载，3=原创
        original_link_url: str = "", # 转载来源URL
        max_workers: int = 5         # 最大上传线程数
    ) -> int:
        """
        上传视频并创建稿件
        
        Args:
            file_path: 视频文件路径
            title: 稿件标题
            channel_id: 频道ID
            cover: 视频封面图片路径
            desc: 稿件简介
            tags: 稿件标签列表
            creation_type: 创作类型 (1=转载，3=原创)
            original_link_url: 转载来源URL
            max_workers: 最大上传线程数
            
        Returns:
            稿件ID (AC号)
        """
        try:
            # 上传视频
            task_id, file_name = self.upload_video(file_path, max_workers)
            
            # 创建视频
            video_id = self.create_video(task_id, file_name)
            
            # 上传封面
            cover_url = self.upload_cover(cover)
            
            # 创建数据
            data = {
                "title": title,
                "description": desc,
                "tagNames": json.dumps(tags),
                "creationType": creation_type,
                "channelId": channel_id,
                "coverUrl": cover_url,
                "videoInfos": json.dumps([{"videoId": video_id, "title": title}]),
                "isJoinUpCollege": "0"
            }
            
            # 添加转载/原创相关信息
            if creation_type == 1:
                data["originalLinkUrl"] = original_link_url
                data["originalDeclare"] = "0"
            else:
                data["originalDeclare"] = "1"
            
            # 发送请求
            headers = {
                **self.DEFAULT_HEADERS,
                "origin": "https://member.acfun.cn",
                "referer": "https://member.acfun.cn/upload-video"
            }
            
            response = self.session.post( # 使用变量 response 存储原始响应
                url=self.ENDPOINTS['create_douga'],
                data=data,
                headers=headers
            )
            try:
                response_json = response.json()
            except json.JSONDecodeError:
                logger.error(f"创建稿件响应非JSON格式: {response.text}")
                raise Exception(f"创建稿件响应非JSON格式: {response.text}")

            # 处理响应
            if response_json.get("result") == 0 and "dougaId" in response_json:
                ac_number = response_json['dougaId']
                logger.info(f"视频投稿成功！AC号：{ac_number}")
                return ac_number
            else:
                # 检查是否是认证错误
                if response.status_code == 401 or (response_json.get("isError") and "401" in str(response_json.get("errMsg"))):
                     logger.error(f"创建稿件失败：认证无效 (401). 响应: {response_json}")
                     raise AuthenticationError(f"创建稿件失败：认证无效 (401). 响应: {response_json}")

                error_detail = f"响应: {response_json}"
                if "result" not in response_json:
                    error_msg = f"'result'键缺失. {error_detail}"
                elif "dougaId" not in response_json and response_json.get("result") == 0:
                     error_msg = f"'dougaId'键缺失但result为0. {error_detail}"
                else:
                    error_msg = response_json.get('error_msg', response_json.get('errMsg', {}).get('message', f"未知错误. {error_detail}"))
                
                logger.error(f"视频投稿失败: {error_msg}")
                raise Exception(f"视频投稿失败: {error_msg}")
        
        except AuthenticationError: # 捕获来自 upload_video 或 create_video/upload_cover 的认证错误
            logger.error("创建稿件过程中发生认证错误，请删除旧的 acfun_cookies.txt 文件并重新运行以使用账号密码登录。")
            # 确保cookie文件被删除，以便下次强制密码登录
            if self.cookie_file.exists():
                self.cookie_file.unlink(missing_ok=True)
                logger.info(f"已删除失效的Cookie文件: {self.cookie_file}")
            raise # 重新抛出，让调用栈最外层处理或用户看到

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AcFun视频上传命令行工具")
    parser.add_argument("-u", "--username", type=str, help="AcFun用户名")
    parser.add_argument("-p", "--password", type=str, help="AcFun密码")
    parser.add_argument("-vf", "--video_file", type=str, required=True, help="视频文件路径")
    parser.add_argument("-cf", "--cover_file", type=str, required=True, help="封面图片路径")
    parser.add_argument("-t", "--title", type=str, required=True, help="稿件标题")
    parser.add_argument("-d", "--description", type=str, default="", help="稿件简介")
    parser.add_argument("--tags", type=str, nargs='+', default=[], help="稿件标签列表，以空格分隔")
    parser.add_argument("-cid", "--channel_id", type=int, required=True, help="频道ID")
    # parent_channel_id 在 create_douga 中没有直接使用，但可以保留以备将来扩展或校验
    # parser.add_argument("-pcid", "--parent_channel_id", type=int, required=True, help="父频道ID") 
    parser.add_argument("--type", type=int, default=3, choices=[1, 3], help="投稿类型 (1=转载, 3=原创)，默认为3 (原创)")
    parser.add_argument("--original_link", type=str, default="", help="转载来源URL (仅当type=1时有效)")
    parser.add_argument("--cookie_file", type=str, default=None, help="Cookie文件路径 (默认为 config/acfun_cookies.txt)")
    parser.add_argument("--max_workers", type=int, default=5, help="最大上传线程数")

    args = parser.parse_args()

    uploader = AcFun(cookie_file=args.cookie_file)

    try:
        # 尝试执行一个需要认证的操作，如果失败，则提示登录
        # 这里直接调用 create_douga，它内部会处理认证失败并尝试删除cookie
        logger.info("开始上传流程...")
        ac_num = uploader.create_douga(
            file_path=args.video_file,
            cover=args.cover_file,
            title=args.title,
            desc=args.description,
            tags=args.tags,
            channel_id=args.channel_id,
            creation_type=args.type,
            original_link_url=args.original_link,
            max_workers=args.max_workers
        )
        if ac_num:
            logger.info(f"视频上传并提交成功！AC号: {ac_num}")
        else:
            logger.error("视频上传或提交失败，请检查日志获取更多信息。")

    except AuthenticationError:
        logger.error("认证失败。如果提供了用户名和密码，将尝试登录。")
        if args.username and args.password:
            if uploader.login(args.username, args.password):
                logger.info("登录成功。请重新运行上传命令。")
            else:
                logger.error("使用提供的用户名和密码登录失败。")
        else:
            logger.info("未提供用户名和密码。请删除旧的cookie文件 (如果存在) 并使用 --username 和 --password 参数重新运行以登录。")
    except FileNotFoundError as e:
        logger.error(f"文件未找到: {e}. 请确保视频和封面文件路径正确。")
    except Exception as e:
        logger.error(f"上传过程中发生未知错误: {e}")
        import traceback
        logger.error(traceback.format_exc())