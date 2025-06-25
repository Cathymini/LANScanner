import sqlite3

def init_database():
    # 连接到数据库（会自动创建文件）
    conn = sqlite3.connect("data/cve_data.db")
    cursor = conn.cursor()
    
    # 创建表
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY,
        cms_name TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        description TEXT,
        severity TEXT,
        cvss_score REAL
    )
    """)
    
    # 插入示例数据
    cve_samples = [
        (1, 'microsoft iis', 'CVE-2023-1234', 'IIS 远程代码执行漏洞', '高危', 9.8),
        (2, 'microsoft iis', 'CVE-2022-4567', 'IIS 拒绝服务漏洞', '中危', 6.5),
        (3, 'wordpress', 'CVE-2023-8910', 'WP 核心XSS漏洞', '高危', 8.2),
        (4, 'WordPress', 'CVE-2023-2345', 'WP Core CSRF漏洞', '中危', 6.5),
        (5, 'Joomla', 'CVE-2023-6789', 'Joomla模板文件包含漏洞', '高危', 8.2),
        (6, 'Drupal', 'CVE-2023-1012', 'Drupal用户权限提升漏洞', '严重', 9.5),
        (7, 'WordPress', 'CVE-2023-3456', 'WP Core任意文件上传漏洞', '高危', 8.8),
        (8, 'Joomla', 'CVE-2023-7890', 'Joomla用户管理模块漏洞', '中危', 6.1),
        (9, 'Drupal', 'CVE-2023-1123', 'Drupal核心模块SQL注入', '严重', 9.8),
        (10, 'WordPress', 'CVE-2023-4567', 'WP Core信息泄露漏洞', '低危', 4.3),
        (11, 'Joomla', 'CVE-2023-8901', 'Joomla插件权限绕过漏洞', '高危', 8.5),
        (12, 'Drupal', 'CVE-2023-1234', 'Drupal模块远程命令执行漏洞', '严重', 9.9),
        (13, 'WordPress', 'CVE-2023-5678', 'WP Core跨站脚本漏洞', '中危', 6.8),
        (14, 'Joomla', 'CVE-2023-9012', 'Joomla模板跨站脚本漏洞', '高危', 8.8),
        (15, 'Drupal', 'CVE-2023-2345', 'Drupal核心模块权限绕过漏洞', '严重', 9.5),
        (16, 'WordPress', 'CVE-2023-6789', 'WP Core远程代码执行漏洞', '严重', 9.8),
        (17, 'Joomla', 'CVE-2023-1012', 'Joomla插件SQL注入漏洞', '高危', 8.2),
        (18, 'Drupal', 'CVE-2023-3456', 'Drupal模块信息泄露漏洞', '低危', 4.5),
        (19, 'WordPress', 'CVE-2023-7890', 'WP Core文件包含漏洞', '高危', 8.8),
        (20, 'Joomla', 'CVE-2023-1123', 'Joomla用户管理模块权限绕过漏洞', '中危', 6.1),
        (21, 'Drupal', 'CVE-2023-4567', 'Drupal核心模块跨站脚本漏洞', '严重', 9.8),
        (22, 'WordPress', 'CVE-2023-8901', 'WP Core用户权限提升漏洞', '高危', 8.5),
        (23, 'Joomla', 'CVE-2023-1234', 'Joomla插件信息泄露漏洞', '低危', 4.3),
        (24, 'Drupal', 'CVE-2023-5678', 'Drupal模块SQL注入漏洞', '严重', 9.9),
        (25, 'WordPress', 'CVE-2023-9012', 'WP Core远程命令执行漏洞', '严重', 9.8),
        (26, 'Joomla', 'CVE-2023-2345', 'Joomla模板文件包含漏洞', '高危', 8.8),
        (27, 'Drupal', 'CVE-2023-6789', 'Drupal核心模块权限提升漏洞', '严重', 9.5),
        (28, 'WordPress', 'CVE-2023-1012', 'WP Core信息泄露漏洞', '低危', 4.5),
        (29, 'Joomla', 'CVE-2023-3456', 'Joomla插件跨站脚本漏洞', '中危', 6.8),
        (30, 'Drupal', 'CVE-2023-7890', 'Drupal模块SQL注入漏洞', '严重', 9.8),
        (31, 'web server', 'CVE-2023-12345', 'Web Server 信息泄露漏洞', '中危', 6.0),
        (32, 'web server', 'CVE-2023-23456', 'Web Server 远程代码执行漏洞', '高危', 8.5),
        (33, 'Apache', 'CVE-2023-34567', 'Apache HTTP Server 文件包含漏洞', '高危', 8.8),
        (34, 'Apache', 'CVE-2023-45678', 'Apache HTTP Server 拒绝服务漏洞', '中危', 6.5),
        (35, 'Apache', 'CVE-2023-56789', 'Apache HTTP Server 权限提升漏洞', '严重', 9.5),
    ]
    
    cursor.executemany(
        "INSERT INTO cves VALUES (?, ?, ?, ?, ?, ?)",
        cve_samples
    )
    
    conn.commit()
    conn.close()
    print("数据库初始化完成！")

if __name__ == "__main__":
    init_database()