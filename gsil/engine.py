# -*- coding: utf-8 -*-

"""
    engine
    ~~~~~~

    Implements Github search engine

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/FeeiCN/gsil
    :license:   GPL, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""

import re
import socket
import traceback
import requests
from github import Github, GithubException
from bs4 import BeautifulSoup
from gsil.config import Config, public_mail_services, exclude_repository_rules, exclude_codes_rules
from .process import Process, clone
from IPy import IP
from tld import get_tld
from .log import logger

# 正则表达式，用于匹配邮箱、主机、密码等敏感信息
regex_mail = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"
regex_host = r"@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"
regex_pass = r"(pass|password|pwd)"
regex_title = r"<title>(.*)<\/title>"
regex_ip = r"^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$"

# 每页返回的最大条目数，提高效率减少请求次数
per_page = 50

# 默认扫描页数，可根据实际需求调整
default_pages = 4

class Engine(object):
    """
    GitHub 搜索引擎核心类，实现自动化敏感信息检测与结果处理
    """

    def __init__(self, token):
        """
        初始化方法，设置 GitHub API token 并初始化相关属性
        :param token: GitHub 访问令牌
        """
        self.token = token
        # 初始化 GitHub API 客户端
        self.g = Github(login_or_token=token, per_page=per_page)
        self.rule_object = None
        self.code = ''
        self.full_name = ''
        self.sha = ''
        self.url = ''
        self.path = ''

        self.result = None           # 存放最终检测到的敏感信息结果
        self.exclude_result = None   # 存放疑似误报结果，后续可人工核查
        self.hash_list = None        # 记录已处理过的代码哈希，避免重复
        self.processed_count = None  # 已处理的条目数（包括跳过）
        self.next_count = None       # 实际处理成功的条目数

    def process_pages(self, pages_content, page, total):
        """
        处理单页搜索结果，筛选、分类、去重、误报处理
        :param pages_content: 单页内容列表
        :param page: 当前页码
        :param total: 总结果数
        :return: True-继续处理后续页面，False-跳过当前规则
        """
        for index, content in enumerate(pages_content):
            current_i = page * per_page + index
            base_info = f'[{self.rule_object.keyword}] [{current_i}/{total}]'

            # 已经连续遇到多条“已处理过”的，直接跳过整个规则，避免浪费资源
            if self.next_count == 0 and self.processed_count > 3:
                logger.info(
                    f'{base_info} Has encountered {self.processed_count} has been processed, skip the current rules!')
                return False

            # 记录本条目的网页链接
            self.url = content.html_url

            # 获取 sha（唯一标识），有异常时跳过
            try:
                self.sha = content.sha
            except Exception as e:
                logger.warning(f'sha exception {e}')
                self.sha = ''
                self.url = ''

            # 检查是否已处理过该 sha
            if self.sha in self.hash_list:
                logger.info(f'{base_info} Processed, skip! ({self.processed_count})')
                self.processed_count += 1
                continue

            # 记录代码路径
            self.path = content.path
            # 记录仓库全名（如 owner/repo）
            self.full_name = content.repository.full_name.strip()
            # 仓库路径黑名单过滤
            if self._exclude_repository():
                logger.info(f'{base_info} Excluded because of the path, skip!')
                continue

            # 获取代码正文内容（自动解码为 utf-8）
            try:
                self.code = content.decoded_content.decode('utf-8')
            except Exception as e:
                logger.warning(f'Get Content Exception: {e} retrying...')
                continue

            # 按规则匹配敏感内容
            match_codes = self.codes()
            if len(match_codes) == 0:
                logger.info(f'{base_info} Did not match the code, skip!')
                continue

            # 构造本条扫描结果
            result = {
                'url': self.url,
                'match_codes': match_codes,
                'hash': self.sha,
                'code': self.code,
                'repository': self.full_name,
                'path': self.path,
            }
            # 代码内容进一步误报过滤，如果可能是无用信息，则放入疑似误报列表
            if self._exclude_codes(match_codes):
                logger.info(f'{base_info} Code may be useless, do not skip, add to list to be reviewed!')
                self.exclude_result[current_i] = result
            else:
                self.result[current_i] = result

            # 如有命中结果，则自动下载对应仓库代码（可选后续进一步分析）
            git_url = content.repository.html_url
            clone(git_url, self.sha)
            logger.info(f'{base_info} Processing is complete, the next one!')
            self.next_count += 1

        return True

    def verify(self):
        """
        校验 GitHub 访问令牌的有效性和 API 配额
        :return: (是否成功, 信息)
        """
        try:
            ret = self.g.rate_limiting
            return True, f'TOKEN-PASSED: {ret}'
        except GithubException as e:
            return False, f'TOKEN-FAILED: FAILED'

    def search(self, rule_object):
        """
        按规则对象进行 GitHub 代码搜索
        :param rule_object: 搜索规则对象，包含关键字、扩展名、模式等
        :return: (是否成功, 规则对象, 消息/数量)
        """
        self.rule_object = rule_object

        # 处理状态计数器归零
        self.processed_count = 0
        self.next_count = 0

        # 获取账户 API 配额情况
        try:
            rate_limiting = self.g.rate_limiting
            rate_limiting_reset_time = self.g.rate_limiting_resettime
            logger.info('----------------------------')

            # 构造搜索关键字（支持扩展名筛选）
            ext_query = ''
            if self.rule_object.extension is not None:
                for ext in self.rule_object.extension.split(','):
                    ext_query += f'extension:{ext.strip().lower()} '
            keyword = f'{self.rule_object.keyword} {ext_query}'
            logger.info(f'Search keyword: {keyword}')
            # 发起 GitHub 代码搜索
            resource = self.g.search_code(keyword, sort="indexed", order="desc")
        except GithubException as e:
            msg = f'GitHub [search_code] exception(code: {e.status} msg: {e.data} {self.token}'
            logger.critical(msg)
            return False, self.rule_object, msg

        logger.info(
            f'[{self.rule_object.keyword}] Speed Limit Results (Remaining Times / Total Times): {rate_limiting}  Speed limit reset time: {rate_limiting_reset_time}')
        logger.info(
            '[{k}] The expected number of acquisitions: {page}(Pages) * {per}(Per Page) = {total}(Total)'.format(
                k=self.rule_object.keyword, page=default_pages, per=per_page, total=default_pages * per_page))

        # 获取真正返回的总结果数
        try:
            total = resource.totalCount
            logger.info(f'[{self.rule_object.keyword}] The actual number: {total}')
        except socket.timeout as e:
            return False, self.rule_object, e
        except GithubException as e:
            msg = f'GitHub [search_code] exception(code: {e.status} msg: {e.data} {self.token}'
            logger.critical(msg)
            return False, self.rule_object, msg

        # 获取已处理过的 sha 列表（避免重复处理）
        self.hash_list = Config().hash_list()

        # 计算需要处理的页数
        if total < per_page:
            pages = 1
        else:
            pages = default_pages

        # 分页处理搜索结果
        for page in range(pages):
            self.result = {}
            self.exclude_result = {}
            try:
                # 获取当前页搜索结果
                pages_content = resource.get_page(page)
            except socket.timeout:
                logger.info(f'[{self.rule_object.keyword}] [get_page] Time out, skip to get the next page！')
                continue
            except GithubException as e:
                msg = f'GitHub [get_page] exception(code: {e.status} msg: {e.data} {self.token}'
                logger.critical(msg)
                return False, self.rule_object, msg

            logger.info(f'[{self.rule_object.keyword}] Get page {page} data for {len(pages_content)}')
            if not self.process_pages(pages_content, page, total):
                # 若遇到多条已处理过的直接跳出本规则
                break
            # 每一页处理完生成一次报告
            Process(self.result, self.rule_object).process()
            # 暂时不自动处理疑似误报，可根据需要解开
            # Process(self.exclude_result, self.rule_object).process(True)

        logger.info(
            f'[{self.rule_object.keyword}] The current rules are processed, the process of normal exit!')
        return True, self.rule_object, len(self.result)

    def codes(self):
        """
        按规则对象的匹配模式处理当前代码，返回匹配的片段列表
        :return: 匹配到的代码行/片段列表
        """
        # 去除图片标签，防止误判
        self.code = self.code.replace('<img', '')
        codes = self.code.splitlines()
        codes_len = len(codes)
        keywords = self._keywords()
        match_codes = []

        # 邮箱模式：直接提取非公开邮箱
        if self.rule_object.mode == 'mail':
            return self._mail()
        # 仅匹配包含关键词的行
        elif self.rule_object.mode == 'only-match':
            for code in codes:
                for kw in keywords:
                    if kw in code:
                        match_codes.append(code)
            return match_codes
        # 匹配包含关键词的行及其上下 3 行
        elif self.rule_object.mode == 'normal-match':
            for idx, code in enumerate(codes):
                for keyword in keywords:
                    if keyword in code:
                        idxs = []
                        # 匹配前 3 行
                        for i in range(-3, -0):
                            i_idx = idx + i
                            if i_idx in idxs:
                                continue
                            if i_idx < 0:
                                continue
                            if codes[i_idx].strip() == '':
                                continue
                            logger.debug(f'P:{i_idx}/{codes_len}: {codes[i_idx]}')
                            idxs.append(i_idx)
                            match_codes.append(codes[i_idx])
                        # 当前行
                        if idx not in idxs:
                            logger.debug(f'C:{idx}/{codes_len}: {codes[idx]}')
                            match_codes.append(codes[idx])
                        # 匹配后 3 行
                        for i in range(1, 4):
                            i_idx = idx + i
                            if i_idx in idxs:
                                continue
                            if i_idx >= codes_len:
                                continue
                            if codes[i_idx].strip() == '':
                                continue
                            logger.debug(f'N:{i_idx}/{codes_len}: {codes[i_idx]}')
                            idxs.append(i_idx)
                            match_codes.append(codes[i_idx])
            return match_codes
        else:
            # 默认返回前 20 行
            return self.code.splitlines()[0:20]

    def _keywords(self):
        """
        解析规则对象中的关键字，支持多关键字和带引号的情况
        :return: 关键字列表
        """
        # 关键字未加引号且包含空格，按空格拆分
        if '"' not in self.rule_object.keyword and ' ' in self.rule_object.keyword:
            return self.rule_object.keyword.split(' ')
        else:
            # 加引号或单关键字
            if '"' in self.rule_object.keyword:
                return [self.rule_object.keyword.replace('"', '')]
            else:
                return [self.rule_object.keyword]

    def _mail(self):
        """
        邮箱提取与归属判定，过滤公开邮箱，尝试获取域名网站标题
        :return: 匹配到的邮箱片段列表
        """
        logger.info(f'[{self.rule_object.keyword}] mail rule')
        match_codes = []
        mails = []
        # 正则提取所有邮箱
        mail_multi = re.findall(regex_mail, self.code)
        for mm in mail_multi:
            mail = mm.strip().lower()
            if mail in mails:
                logger.info('[SKIPPED] Mail already processed!')
                continue
            # 提取邮箱主机部分
            host = re.findall(regex_host, mail)
            host = host[0].strip()
            # 过滤常见公开邮箱
            if host in public_mail_services:
                logger.info('[SKIPPED] Public mail services!')
                continue
            mails.append(mail)

            # 构造域名（尝试获取主域名及网站标题）
            is_inner_ip = False
            if re.match(regex_ip, host) is None:
                try:
                    top_domain = get_tld(host, fix_protocol=True)
                except Exception as e:
                    logger.warning(f'get top domain exception {e}')
                    top_domain = host
                if top_domain == host:
                    domain = f'http://www.{host}'
                else:
                    domain = f'http://{host}'
            else:
                # 若为内网 IP
                if IP(host).iptype() == 'PRIVATE':
                    is_inner_ip = True
                domain = f'http://{host}'
            title = '<Unknown>'
            # 远程获取网站标题
            if is_inner_ip is False:
                try:
                    response = requests.get(domain, timeout=4).content
                except Exception as e:
                    title = f'<{e}>'
                else:
                    try:
                        soup = BeautifulSoup(response, "html5lib")
                        if hasattr(soup.title, 'string'):
                            title = soup.title.string.strip()[0:150]
                    except Exception as e:
                        title = 'Exception'
                        traceback.print_exc()
            else:
                title = '<Inner IP>'

            match_codes.append(f"{mail} {domain} {title}")
            logger.info(f' - {mail} {domain} {title}')
        return match_codes

    def _exclude_repository(self):
        """
        检查当前仓库路径是否命中排除规则（如 github.io 静态站等）
        :return: True-需排除, False-正常处理
        """
        ret = False
        # 拼接完整的项目路径
        full_path = f'{self.full_name.lower()}/{self.path.lower()}'
        for err in exclude_repository_rules:
            if re.search(err, full_path) is not None:
                return True
        return ret

    @staticmethod
    def _exclude_codes(codes):
        """
        检查代码片段是否命中误报规则（如一些常见无用代码模式）
        :param codes: 匹配到的代码片段
        :return: True-疑似误报, False-正常
        """
        ret = False
        for ecr in exclude_codes_rules:
            if re.search(ecr, '\n'.join(codes)) is not None:
                return True
        return ret
