import sqlite3
import os
from pathlib import Path
from typing import List, Dict

class CVEMatcher:
    def __init__(self, db_path: str = None):
        """
        初始化CVE匹配器
        :param db_path: 可选的自定义数据库路径
        """
        # 自动计算数据库绝对路径
        base_dir = Path(__file__).parent.parent  # 项目根目录
        self.db_path = db_path or str(base_dir / "data" / "cve_data.db")
        
        # 验证数据库文件是否存在
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"CVE数据库文件不存在: {self.db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        """获取数据库连接（带错误处理）"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row  # 允许通过列名访问
            return conn
        except sqlite3.Error as e:
            raise ConnectionError(f"无法连接CVE数据库: {str(e)}")

    def match_cve(self, cms_name: str) -> List[Dict]:
        """
        根据CMS名称匹配CVE漏洞（增强Web Server支持）
        :param cms_name: CMS名称（如"Microsoft IIS"）
        :return: 漏洞列表，格式示例：
            [{
                'cve_id': 'CVE-2023-1234',
                'description': '远程代码执行漏洞',
                'severity': '高危',
                'cvss_score': 9.8
            }]
        """
        if not cms_name:
            return []

        cms_name = cms_name.strip().lower()
        
        # Web Server的别名列表
        web_server_aliases = {
            'web server', 
            'unknown',
            'microsoft iis', 
            'apache', 
            'nginx',
            'iis'
        }

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # 优先精确匹配
                cursor.execute(
                    """SELECT cve_id, description, severity, cvss_score 
                       FROM cves 
                       WHERE LOWER(cms_name) = LOWER(?)
                       ORDER BY cvss_score DESC""",
                    (cms_name,)
                )
                results = [dict(row) for row in cursor.fetchall()]
                
                # 如果没有结果且是Web服务类，则查询通用漏洞
                if not results and cms_name in web_server_aliases:
                    cursor.execute(
                        """SELECT cve_id, description, severity, cvss_score 
                           FROM cves 
                           WHERE LOWER(cms_name) IN ('web server', ?)
                           ORDER BY cvss_score DESC""",
                        (cms_name,)
                    )
                    results = [dict(row) for row in cursor.fetchall()]
                
                # 转换CVSS分数为float
                for item in results:
                    item['cvss_score'] = float(item['cvss_score']) if item['cvss_score'] else 0.0
                
                return results
                
        except Exception as e:
            print(f"[CVE匹配错误] CMS: {cms_name}, 错误: {str(e)}")
            return []

    def get_all_cves(self) -> List[Dict]:
        """获取数据库中所有CVE（用于调试）"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM cves")
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            print(f"[获取全部CVE错误] {str(e)}")
            return []

    def get_web_server_cves(self) -> List[Dict]:
        """专门获取Web Server通用漏洞"""
        return self.match_cve("web server")

# 测试代码
if __name__ == "__main__":
    try:
        print("=== CVE匹配器测试 ===")
        matcher = CVEMatcher()
        
        # 测试1: Web Server漏洞
        print("\n[测试1] Web Server通用漏洞:")
        web_cves = matcher.get_web_server_cves()
        for cve in web_cves:
            print(f"{cve['cve_id']} ({cve['severity']}): {cve['description']}")
        
        # 测试2: 未知服务
        print("\n[测试2] 未知服务测试:")
        print(matcher.match_cve("unknown"))
        
        # 测试3: 数据库内容验证
        print("\n[测试3] 数据库记录统计:")
        all_data = matcher.get_all_cves()
        print(f"总记录数: {len(all_data)}")
        print(f"Web Server漏洞数: {len(matcher.get_web_server_cves())}")
        
    except Exception as e:
        print(f"!!! 测试失败: {str(e)}")