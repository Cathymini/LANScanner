import tkinter as tk
from tkinter import ttk, messagebox
from core.scanner import multi_threaded_scan
from core.fingerprint import load_fingerprints
from core.cve_matcher import CVEMatcher
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib as mpl
from datetime import datetime

# 设置中文字体（任选一种方式）
try:
    # 方式1：使用系统已安装的字体
    mpl.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'WenQuanYi Zen Hei']  # 指定多个候选中文字体
    mpl.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题
    
    # 方式2：直接指定字体文件路径（适用于自定义字体）
    # mpl.rcParams['font.family'] = 'sans-serif'
    # mpl.rcParams['font.sans-serif'] = ['SimHei']  # 或替换为实际字体路径
except Exception as e:
    print(f"字体设置失败: {e}")

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("局域网扫描器 v2.0")
        self.root.geometry("800x600")
        
        # 输入区域
        input_frame = tk.LabelFrame(self.root, text="扫描设置", padx=5, pady=5)
        input_frame.pack(fill="x", padx=10, pady=5)
        
        tk.Label(input_frame, text="IP 地址/范围：").grid(row=0, column=0, sticky="e", padx=5)
        self.ip_range_entry = tk.Entry(input_frame, width=30)
        self.ip_range_entry.grid(row=0, column=1, sticky="w")
        self.ip_range_entry.insert(0, "127.0.0.1")
        
        tk.Label(input_frame, text="端口范围：").grid(row=1, column=0, sticky="e", padx=5)
        self.port_range_entry = tk.Entry(input_frame, width=30)
        self.port_range_entry.grid(row=1, column=1, sticky="w")
        self.port_range_entry.insert(0, "80-90,440-450,8080-8090")
        
        tk.Label(input_frame, text="线程数：").grid(row=2, column=0, sticky="e", padx=5)
        self.num_threads_entry = tk.Entry(input_frame, width=30)
        self.num_threads_entry.grid(row=2, column=1, sticky="w")
        self.num_threads_entry.insert(0, "3")
        
        self.scan_button = tk.Button(
            input_frame, 
            text="开始扫描", 
            command=self.start_scan,
            bg="#4CAF50",
            fg="white"
        )
        self.scan_button.grid(row=3, column=0, columnspan=2, pady=5)

        # 扫描结果区域
        result_frame = tk.LabelFrame(self.root, text="扫描结果", padx=5, pady=5)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.tree = ttk.Treeview(
            result_frame, 
            columns=("IP", "端口", "状态", "服务", "CMS"), 
            show="headings",
            height=10
        )
        
        # 配置表格列
        self.tree.heading("IP", text="IP地址")
        self.tree.heading("端口", text="端口")
        self.tree.heading("状态", text="状态")
        self.tree.heading("服务", text="服务类型")
        self.tree.heading("CMS", text="CMS/框架")
        
        # 设置列宽
        self.tree.column("IP", width=120, anchor="center")
        self.tree.column("端口", width=80, anchor="center")
        self.tree.column("状态", width=80, anchor="center")
        self.tree.column("服务", width=120, anchor="center")
        self.tree.column("CMS", width=150, anchor="center")
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(fill="both", expand=True)
        
        # 绑定点击事件
        self.tree.bind("<<TreeviewSelect>>", self.on_scan_result_select)

        # CVE漏洞详情区域
        cve_frame = tk.LabelFrame(self.root, text="CVE漏洞详情", padx=5, pady=5)
        cve_frame.pack(fill="x", padx=10, pady=5)
        
        self.cve_tree = ttk.Treeview(
            cve_frame, 
            columns=("CVE ID", "严重程度", "CVSS", "描述"), 
            show="headings",
            height=4
        )
        
        # 配置CVE表格
        self.cve_tree.heading("CVE ID", text="CVE ID")
        self.cve_tree.heading("严重程度", text="严重程度")
        self.cve_tree.heading("CVSS", text="CVSS评分")
        self.cve_tree.heading("描述", text="漏洞描述")
        
        self.cve_tree.column("CVE ID", width=100, anchor="center")
        self.cve_tree.column("严重程度", width=80, anchor="center")
        self.cve_tree.column("CVSS", width=80, anchor="center")
        self.cve_tree.column("描述", width=300, anchor="w")
        
        cve_scrollbar = ttk.Scrollbar(cve_frame, orient="horizontal", command=self.cve_tree.xview)
        cve_scrollbar.pack(side="bottom", fill="x")
        self.cve_tree.configure(xscrollcommand=cve_scrollbar.set)
        self.cve_tree.pack(fill="both", expand=True)

        # 报告生成按钮
        self.report_button = tk.Button(
            self.root, 
            text="生成风险评估报告", 
            command=self.generate_report,
            bg="#2196F3",
            fg="white",
            state="disabled"
        )
        self.report_button.pack(pady=5)

    def start_scan(self):
        """执行扫描操作"""
        # 清空旧数据
        for item in self.tree.get_children():
            self.tree.delete(item)
        for item in self.cve_tree.get_children():
            self.cve_tree.delete(item)
        
        try:
            # 获取输入参数
            ip = self.ip_range_entry.get().strip()
            port_ranges = self.port_range_entry.get().split(",")
            num_threads = int(self.num_threads_entry.get())
            
            # 解析端口范围
            ports = []
            for prange in port_ranges:
                if "-" in prange:
                    start, end = map(int, prange.split("-"))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(prange))
            
            # 执行扫描
            results = multi_threaded_scan(ip, (min(ports), max(ports)), num_threads)
            
            # 显示结果
            for port, status, service, cms in results:
                if port in ports:  # 只显示用户指定的端口
                    self.tree.insert("", "end", values=(ip, port, status, service, cms))
            
            self.report_button.config(state="normal")
            messagebox.showinfo("扫描完成", f"扫描完成！共检测 {len(ports)} 个端口")
            
        except Exception as e:
            messagebox.showerror("错误", f"扫描出错: {str(e)}")

    def on_scan_result_select(self, event):
        """当选择扫描结果时显示CVE详情"""
        selected = self.tree.selection()
        if not selected:
            return
            
        # 清空CVE表格
        for item in self.cve_tree.get_children():
            self.cve_tree.delete(item)
        
        # 获取选中的CMS信息
        item = self.tree.item(selected[0])
        cms = item['values'][4]
        
        # 如果不是Web服务则跳过
        if cms in ("unknown", "Web Server"):
            return
            
        # 查询CVE数据
        try:
            matcher = CVEMatcher()
            cves = matcher.match_cve(cms)
            
            if not cves:
                self.cve_tree.insert("", "end", values=("无漏洞", "", "", "未发现已知漏洞"))
            else:
                for cve in cves:
                    self.cve_tree.insert("", "end", values=(cve['cve_id'], cve['severity'], cve['cvss_score'], cve['description']))
        except Exception as e:
            messagebox.showerror("错误", f"查询CVE失败: {str(e)}")

    def generate_report(self):
        """增强的报告生成方法"""
        try:
            # 收集数据
            vuln_data = {}
            open_ports = []
            cve_details = []
            total_vulns = 0
            high_risk = 0
            medium_risk = 0
            low_risk = 0
            
            # 分析扫描结果
            for child in self.tree.get_children():
                item = self.tree.item(child)
                status, port, cms = item['values'][2], item['values'][1], item['values'][4]
                
                if status == "open":
                    open_ports.append(port)
                    if cms.lower() not in ("unknown", "web server"):
                        matcher = CVEMatcher()
                        cves = matcher.match_cve(cms)
                        if cves:
                            vuln_data[cms] = len(cves)
                            total_vulns += len(cves)
                            for cve in cves:
                                cve_details.append({
                                    'cms': cms,
                                    'cve_id': cve['cve_id'],
                                    'severity': cve['severity'],
                                    'cvss': cve['cvss_score'],
                                    'port': port
                                })
                                # 统计风险等级
                                if cve['cvss_score'] >= 7.0:
                                    high_risk += 1
                                elif cve['cvss_score'] >= 4.0:
                                    medium_risk += 1
                                else:
                                    low_risk += 1
            
            # 创建图表和报告内容
            fig = plt.figure(figsize=(12, 8))
            fig.suptitle("网络安全风险评估报告\n" + datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                         fontsize=14, fontweight='bold')
            
            # 使用GridSpec创建更复杂的布局
            gs = fig.add_gridspec(3, 2)
            
            # 1. 风险概览饼图
            ax1 = fig.add_subplot(gs[0, 0])
            risk_data = [high_risk, medium_risk, low_risk]
            risk_labels = ['高危', '中危', '低危']
            risk_colors = ['#ff5252', '#ffc107', '#4caf50']
            
            if sum(risk_data) > 0:
                ax1.pie(
                    risk_data,
                    labels=risk_labels,
                    colors=risk_colors,
                    autopct='%1.1f%%',
                    startangle=90,
                    shadow=True,
                    explode=(0.1, 0, 0)
                )
                ax1.set_title("风险等级分布", fontweight='bold')
            else:
                ax1.text(0.5, 0.5, "未检测到漏洞", ha="center", va="center")
                ax1.set_title("无风险")
            
            # 2. 开放端口热力图
            ax2 = fig.add_subplot(gs[0, 1])
            if open_ports:
                # 将端口分组显示
                port_groups = {}
                for port in open_ports:
                    group = f"{port//100*100}-{port//100*100+99}"
                    port_groups[group] = port_groups.get(group, 0) + 1
                
                groups = sorted(port_groups.keys())
                counts = [port_groups[g] for g in groups]
                
                bars = ax2.barh(groups, counts, color='#2196F3')
                ax2.bar_label(bars, padding=3)
                ax2.set_xlabel("开放端口数量")
                ax2.set_title(f"开放端口分布 (共{len(open_ports)}个)", fontweight='bold')
            else:
                ax2.text(0.5, 0.5, "未检测到开放端口", ha="center", va="center")
                ax2.set_title("无开放端口")
            
            # 3. CMS漏洞分布
            ax3 = fig.add_subplot(gs[1, :])
            if vuln_data:
                cms_names = list(vuln_data.keys())
                vuln_counts = list(vuln_data.values())
                
                bars = ax3.bar(cms_names, vuln_counts, color='#9C27B0')
                ax3.bar_label(bars, padding=3)
                ax3.set_ylabel("漏洞数量")
                ax3.set_title("各CMS/框架漏洞数量", fontweight='bold')
                plt.setp(ax3.get_xticklabels(), rotation=15, ha="right")
            else:
                ax3.text(0.5, 0.5, "未检测到CMS漏洞", ha="center", va="center")
                ax3.set_title("无CMS漏洞")
            
            # 4. 关键漏洞表格
            ax4 = fig.add_subplot(gs[2, :])
            ax4.axis('off')
            
            if cve_details:
                # 按CVSS评分排序
                cve_details.sort(key=lambda x: x['cvss'], reverse=True)
                top_cves = cve_details[:5]  # 显示前5个最严重的漏洞
                
                # 创建表格数据
                table_data = [['CVE ID', 'CMS', '端口', 'CVSS', '风险等级']]
                for cve in top_cves:
                    table_data.append([
                        cve['cve_id'],
                        cve['cms'],
                        cve['port'],
                        f"{cve['cvss']:.1f}",
                        cve['severity']
                    ])
                
                # 绘制表格
                table = ax4.table(
                    cellText=table_data,
                    loc='center',
                    cellLoc='center',
                    colWidths=[0.2, 0.2, 0.1, 0.1, 0.2]
                )
                table.auto_set_font_size(False)
                table.set_fontsize(10)
                table.scale(1, 1.5)
                
                # 设置表头样式
                for (i, j), cell in table.get_celld().items():
                    if i == 0:
                        cell.set_text_props(fontweight='bold')
                        cell.set_facecolor('#607D8B')
                        cell.set_text_props(color='white')
                
                ax4.set_title("关键漏洞列表 (按严重程度排序)", fontweight='bold')
            else:
                ax4.text(0.5, 0.5, "未检测到关键漏洞", ha="center", va="center")
            
            plt.tight_layout()
            
            # 显示报告窗口
            report_window = tk.Toplevel(self.root)
            report_window.title("风险评估报告 - " + datetime.now().strftime("%Y%m%d"))
            report_window.geometry("1000x800")
            
            canvas = FigureCanvasTkAgg(fig, master=report_window)
            canvas.draw()
            canvas.get_tk_widget().pack(fill="both", expand=True)
            
            # 添加保存按钮和修复建议
            button_frame = tk.Frame(report_window)
            button_frame.pack(fill="x", pady=5)
            
            save_button = tk.Button(
                button_frame,
                text="保存报告为PNG",
                command=lambda: self.save_report(fig),
                bg="#607D8B",
                fg="white",
                width=15
            )
            save_button.pack(side="left", padx=10)
            
            # 添加修复建议按钮
            if total_vulns > 0:
                advice_button = tk.Button(
                    button_frame,
                    text="查看修复建议",
                    command=lambda: self.show_recommendations(cve_details),
                    bg="#FF9800",
                    fg="white",
                    width=15
                )
                advice_button.pack(side="left", padx=10)
            
            # 关闭图表防止内存泄漏
            plt.close(fig)

        except Exception as e:
            messagebox.showerror("生成报告错误", f"无法生成报告: {str(e)}")
            print(f"完整错误信息: {repr(e)}")

    def show_recommendations(self, cve_details):
        """显示修复建议"""
        rec_window = tk.Toplevel(self.root)
        rec_window.title("安全修复建议")
        rec_window.geometry("800x600")
        
        # 按风险等级排序
        cve_details.sort(key=lambda x: x['cvss'], reverse=True)
        
        # 创建文本区域
        text_frame = tk.Frame(rec_window)
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")
        
        text_area = tk.Text(
            text_frame,
            wrap="word",
            yscrollcommand=scrollbar.set,
            font=("Microsoft YaHei", 10)
        )
        text_area.pack(fill="both", expand=True)
        scrollbar.config(command=text_area.yview)
        
        # 添加标题
        text_area.insert("end", "安全修复建议\n", "title")
        text_area.tag_configure("title", font=("Microsoft YaHei", 14, "bold"), justify="center")
        text_area.insert("end", "\n")
        
        # 添加摘要信息
        high_count = sum(1 for cve in cve_details if cve['cvss'] >= 7.0)
        text_area.insert("end", 
            f"共发现 {len(cve_details)} 个漏洞，其中 {high_count} 个高危漏洞。\n\n",
            "summary"
        )
        text_area.tag_configure("summary", font=("Microsoft YaHei", 11))
        
        # 添加每个漏洞的建议
        for idx, cve in enumerate(cve_details, 1):
            text_area.insert("end", f"{idx}. {cve['cve_id']} ({cve['severity']}, CVSS: {cve['cvss']:.1f})\n", "cve_header")
            text_area.tag_configure("cve_header", font=("Microsoft YaHei", 11, "bold"), foreground="red" if cve['cvss'] >= 7.0 else "orange")
            
            text_area.insert("end", f"   - 受影响服务: {cve['cms']} (端口: {cve['port']})\n")
            
            # 这里可以添加更具体的修复建议
            text_area.insert("end", "   - 修复建议:\n")
            if cve['cms'].lower() == "wordpress":
                text_area.insert("end", "     * 立即更新WordPress到最新版本\n")
                text_area.insert("end", "     * 禁用不必要的插件\n")
            elif cve['cms'].lower() == "joomla":
                text_area.insert("end", "     * 更新Joomla核心和所有扩展\n")
            else:
                text_area.insert("end", "     * 更新软件到最新版本\n")
            
            text_area.insert("end", "     * 限制受影响端口的访问权限\n")
            text_area.insert("end", "     * 考虑使用Web应用防火墙(WAF)\n")
            
            text_area.insert("end", "\n")
        
        # 添加通用建议
        text_area.insert("end", "\n通用安全建议:\n", "general_header")
        text_area.tag_configure("general_header", font=("Microsoft YaHei", 11, "bold"))
        
        general_advice = [
            "1. 定期更新所有软件和系统补丁",
            "2. 关闭不必要的服务和端口",
            "3. 实施最小权限原则",
            "4. 定期备份重要数据",
            "5. 启用日志记录和监控",
            "6. 对员工进行安全意识培训"
        ]
        
        for advice in general_advice:
            text_area.insert("end", f"   - {advice}\n")
        
        text_area.config(state="disabled")
        
        # 添加保存按钮
        save_button = tk.Button(
            rec_window,
            text="保存建议为文本文件",
            command=lambda: self.save_text_report(text_area.get("1.0", "end")),
            bg="#4CAF50",
            fg="white"
        )
        save_button.pack(pady=10)

    def save_text_report(self, text):
        """保存文本报告"""
        try:
            with open("security_recommendations.txt", "w", encoding="utf-8") as f:
                f.write(text)
            messagebox.showinfo("成功", "修复建议已保存为 security_recommendations.txt")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {str(e)}")

    def save_report(self, fig):
        """增强的报告保存功能"""
        try:
            # 添加时间戳到文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.png"
            
            fig.savefig(filename, dpi=300, bbox_inches="tight")
            messagebox.showinfo("成功", f"报告已保存为 {filename}")
        except Exception as e:
            messagebox.showerror("错误", f"保存失败: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()