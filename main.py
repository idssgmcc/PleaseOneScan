import tkinter as tk
from tkinter import ttk, messagebox
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'vulnerability_scanners'))

from vulnerability_scanners.starrocks import check_starrocks
from vulnerability_scanners.casdoor import check_casdoor
from vulnerability_scanners.easycvr_userlist import check_easycvr_userlist
from vulnerability_scanners.easycvr_adduser import check_easycvr_adduser
from vulnerability_scanners.nuuo_rce import check_nuuo_rce
from vulnerability_scanners.sangfor_ngaf import check_sangfor_ngaf
from vulnerability_scanners.hongyun import check_hongyun
from vulnerability_scanners.doccms_sqli import check_doccms_sqli
from vulnerability_scanners.landray_upload import check_landray_upload
from vulnerability_scanners.landray_sqli import check_landray_sqli
from vulnerability_scanners.hongfan_ioffice import check_hongfan_ioffice
from vulnerability_scanners.jsh_erp_info_leak import check_jsh_erp_info_leak
from vulnerability_scanners.jsh_erp_cve_2024_0490 import check_jsh_erp_cve_2024_0490
from vulnerability_scanners.hfoffice_sqli import check_hfoffice_sqli
from vulnerability_scanners.dahua_dss_itc_bulletin_sqli import check_dahua_dss_itc_bulletin_sqli
from vulnerability_scanners.dahua_dss_user_edit_info_leak import check_dahua_dss_user_edit_info_leak
from vulnerability_scanners.dahua_dss_attachment_clearTempFile_sqli import check_dahua_dss_attachment_clearTempFile_sqli
from vulnerability_scanners.dahua_icc_file_read import check_dahua_icc_file_read
from vulnerability_scanners.dahua_icc_random_rce import check_dahua_icc_random_rce
from vulnerability_scanners.dahua_icc_log4j_rce import check_dahua_icc_log4j_rce
from vulnerability_scanners.dahua_icc_fastjson_rce import check_dahua_icc_fastjson_rce
from vulnerability_scanners.yonyou_nc_file_upload import check_yonyou_nc_file_upload
from vulnerability_scanners.yonyou_nc_jndi_rce import check_yonyou_nc_jndi_rce
from vulnerability_scanners.yonyou_nc_linkVoucher_sqli import check_yonyou_nc_linkVoucher_sqli
from vulnerability_scanners.yonyou_nc_showcontent_sqli import check_yonyou_nc_showcontent_sqli
from vulnerability_scanners.yonyou_nc_grouptemplet_file_upload import check_yonyou_nc_grouptemplet_file_upload
from vulnerability_scanners.yonyou_nc_down_bill_sqli import check_yonyou_nc_down_bill_sqli
from vulnerability_scanners.yonyou_nc_importPml_sqli import check_yonyou_nc_importPml_sqli
from vulnerability_scanners.yonyou_nc_runStateServlet_sqli import check_yonyou_nc_runStateServlet_sqli
from vulnerability_scanners.yonyou_nc_complainbilldetail_sqli import check_yonyou_nc_complainbilldetail_sqli
from vulnerability_scanners.yonyou_nc_downTax_download_sqli import check_yonyou_nc_downTax_download_sqli
from vulnerability_scanners.yonyou_nc_warningDetailInfo_sqli import check_yonyou_nc_warningDetailInfo_sqli
from vulnerability_scanners.yonyou_nc_cloud_importhttpscer_file_upload import check_yonyou_nc_cloud_importhttpscer_file_upload
from vulnerability_scanners.yonyou_nc_cloud_soapFormat_xxe import check_yonyou_nc_cloud_soapFormat_xxe
from vulnerability_scanners.yonyou_nc_cloud_IUpdateService_xxe import check_yonyou_nc_cloud_IUpdateService_xxe
from vulnerability_scanners.yonyou_u8_cloud_smartweb2_rpc_xxe import check_yonyou_u8_cloud_smartweb2_rpc_xxe
from vulnerability_scanners.yonyou_u8_cloud_registerServlet_sqli import check_yonyou_u8_cloud_registerServlet_sqli
from vulnerability_scanners.yonyou_u8_cloud_XChangeServlet_xxe import check_yonyou_u8_cloud_XChangeServlet_xxe
from vulnerability_scanners.yonyou_u8_cloud_MeasureQueryByToolAction_sqli import check_yonyou_u8_cloud_MeasureQueryByToolAction_sqli
from vulnerability_scanners.yonyou_grp_u8_SmartUpload01_file_upload import check_yonyou_grp_u8_SmartUpload01_file_upload
from vulnerability_scanners.yonyou_grp_u8_userInfoWeb_sqli_rce import check_yonyou_grp_u8_userInfoWeb_sqli_rce
from vulnerability_scanners.yonyou_grp_u8_bx_dj_check_sqli import check_yonyou_grp_u8_bx_dj_check_sqli
from vulnerability_scanners.yonyou_grp_u8_ufgovbank_xxe import check_yonyou_grp_u8_ufgovbank_xxe
from vulnerability_scanners.yonyou_grp_u8_sqcxIndex_sqli import check_yonyou_grp_u8_sqcxIndex_sqli
from vulnerability_scanners.yonyou_grp_a_plus_cloud_file_read import check_yonyou_grp_a_plus_cloud_file_read
from vulnerability_scanners.yonyou_u8_crm_swfupload_file_upload import check_yonyou_u8_crm_swfupload_file_upload
from vulnerability_scanners.yonyou_u8_crm_uploadfile_file_upload import check_yonyou_u8_crm_uploadfile_file_upload
from vulnerability_scanners.qdocs_smart_school_sqli import check_qdocs_smart_school_sqli
from vulnerability_scanners.yunshikong_erp_validateLoginName_sqli import check_yunshikong_erp_validateLoginName_sqli
from vulnerability_scanners.fanwei_eoffice_json_common_sqli import check_fanwei_eoffice_json_common_sqli
from vulnerability_scanners.dptech_vpn_file_upload import check_dptech_vpn_file_upload
from vulnerability_scanners.tplus_getstorewarehousebystore_rce import check_tplus_getstorewarehousebystore_rce
from vulnerability_scanners.tplus_getdecallusers_info_leak import check_tplus_getdecallusers_info_leak
from vulnerability_scanners.tplus_RRATableController_rce import check_tplus_RRATableController_rce
from vulnerability_scanners.tplus_keyEdit_sqli import check_tplus_keyEdit_sqli
from vulnerability_scanners.tplus_KeyInfoList_sqli import check_tplus_KeyInfoList_sqli
from vulnerability_scanners.xetux_dynamiccontent_rce import check_xetux_dynamiccontent_rce
from vulnerability_scanners.baizhuo_smart_importexport_sqli import check_baizhuo_smart_importexport_sqli

class VulnerabilityScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("khan安全攻防实验室")

        self.top_frame = tk.Frame(root)
        self.top_frame.pack(pady=10)

        self.label = tk.Label(self.top_frame, text="Enter URL:")
        self.label.pack(side=tk.LEFT, padx=5)

        self.entry = tk.Entry(self.top_frame, width=50)
        self.entry.pack(side=tk.LEFT, padx=5)

        self.script_label = tk.Label(self.top_frame, text="Select Script:")
        self.script_label.pack(side=tk.LEFT, padx=5)

        self.script_options = [
            "StarRocks MPP数据库未授权访问",
            "Casdoor系统static任意文件读取",
            "EasyCVR智能边缘网关 userlist 信息泄漏",
            "EasyCVR视频管理平台存在任意用户添加",
            "NUUO NVR 视频存储管理设备远程命令执行",
            "深信服 NGAF 任意文件读取",
            "鸿运主动安全监控云平台任意文件下载",
            "稻壳CMS keyword 未授权SQL注入",
            "蓝凌EIS智慧协同平台api.aspx任意文件上传",
            "蓝凌EIS智慧协同平台 doc_fileedit_word.aspx SQL注入",
            "红帆iOffice ioFileDown任意文件读取",
            "华夏ERP（jshERP）敏感信息泄露",
            "华夏ERP getAllList信息泄露 (CVE-2024-0490)",
            "红帆HFOffice医微云SQL注入",
            "大华 DSS itcBulletin SQL 注入",
            "大华 DSS 数字监控系统 user_edit.action 信息泄露",
            "大华 DSS 数字监控系统 attachment_clearTempFile.action SQL注入",
            "大华ICC智能物联综合管理平台任意文件读取",
            "大华ICC智能物联综合管理平台random远程代码执行",
            "大华ICC智能物联综合管理平台 log4j远程代码执行",
            "大华ICC智能物联综合管理平台 fastjson远程代码执行",
            "用友NC 6.5 accept.jsp任意文件上传",
            "用友NC registerServlet JNDI 远程代码执行",
            "用友NC linkVoucher SQL注入",
            "用友NC showcontent SQL注入",
            "用友NC grouptemplet 任意文件上传",
            "用友NC down/bill SQL注入",
            "用友NC importPml SQL注入",
            "用友NC runStateServlet SQL注入",
            "用友NC complainbilldetail SQL注入",
            "用友NC downTax/download SQL注入",
            "用友NC warningDetailInfo接口SQL注入",
            "用友NC-Cloud importhttpscer任意文件上传",
            "用友NC-Cloud soapFormat XXE",
            "用友NC-Cloud IUpdateService XXE",
            "用友U8 Cloud smartweb2.RPC.d XXE",
            "用友U8 Cloud RegisterServlet SQL注入",
            "用友U8-Cloud XChangeServlet XXE",
            "用友U8 Cloud MeasureQueryByToolAction SQL注入",
            "用友GRP-U8 SmartUpload01 文件上传",
            "用友GRP-U8 userInfoWeb SQL注入致RCE",
            "用友GRP-U8 bx_dj_check.jsp SQL注入",
            "用友GRP-U8 ufgovbank XXE",
            "用友GRP-U8 sqcxIndex.jsp SQL注入",
            "用友GRP A++Cloud 政府财务云 任意文件读取",
            "用友U8 CRM swfupload 任意文件上传",
            "用友U8 CRM系统uploadfile.php接口任意文件上传",
            "QDocs Smart School 6.4.1 filterRecords SQL注入",
            "云时空社会化商业 ERP 系统 validateLoginName SQL 注入",
            "泛微E-Office json_common.php sql注入",
            "迪普 DPTech VPN Service 任意文件上传",
            "畅捷通T+ getstorewarehousebystore 远程代码执行",
            "畅捷通T+ getdecallusers信息泄露",
            "畅捷通T+ RRATableController,Ufida.T.DI.UIP.ashx 反序列化RCE",
            "畅捷通T+ keyEdit.aspx SQL注入",
            "畅捷通T+ KeyInfoList.aspx SQL注入",
            "XETUX 软件 dynamiccontent.properties.xhtml 远程代码执行",
            "百卓Smart管理平台 importexport.php SQL注入"
        ]
        self.script_var = tk.StringVar()
        self.script_dropdown = ttk.Combobox(self.top_frame, textvariable=self.script_var, values=self.script_options, width=50)
        self.script_dropdown.pack(side=tk.LEFT, padx=5)

        self.scan_button = tk.Button(root, text="Scan", command=self.scan)
        self.scan_button.pack(pady=10)

        self.result_text = tk.Text(root, height=20, width=80)
        self.result_text.pack(pady=10)

    def scan(self):
        url = self.entry.get()
        script = self.script_var.get()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
        if not script:
            messagebox.showerror("Error", "Please select a script")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Scanning {url} with {script} script...\n")
        self.result_text.update_idletasks()

        self.scan_button.config(state=tk.DISABLED)

        try:
            result = ""
            if script == "StarRocks MPP数据库未授权访问":
                result = check_starrocks(url)
            elif script == "Casdoor系统static任意文件读取":
                result = check_casdoor(url)
            elif script == "EasyCVR智能边缘网关 userlist 信息泄漏":
                result = check_easycvr_userlist(url)
            elif script == "EasyCVR视频管理平台存在任意用户添加":
                result = check_easycvr_adduser(url)
            elif script == "NUUO NVR 视频存储管理设备远程命令执行":
                result = check_nuuo_rce(url)
            elif script == "深信服 NGAF 任意文件读取":
                result = check_sangfor_ngaf(url)
            elif script == "鸿运主动安全监控云平台任意文件下载":
                result = check_hongyun(url)
            elif script == "稻壳CMS keyword 未授权SQL注入":
                result = check_doccms_sqli(url)
            elif script == "蓝凌EIS智慧协同平台api.aspx任意文件上传":
                result = check_landray_upload(url)
            elif script == "蓝凌EIS智慧协同平台 doc_fileedit_word.aspx SQL注入":
                result = check_landray_sqli(url)
            elif script == "红帆iOffice ioFileDown任意文件读取":
                result = check_hongfan_ioffice(url)
            elif script == "华夏ERP（jshERP）敏感信息泄露":
                result = check_jsh_erp_info_leak(url)
            elif script == "华夏ERP getAllList信息泄露 (CVE-2024-0490)":
                result = check_jsh_erp_cve_2024_0490(url)
            elif script == "红帆HFOffice医微云SQL注入":
                result = check_hfoffice_sqli(url)
            elif script == "大华 DSS itcBulletin SQL 注入":
                result = check_dahua_dss_itc_bulletin_sqli(url)
            elif script == "大华 DSS 数字监控系统 user_edit.action 信息泄露":
                result = check_dahua_dss_user_edit_info_leak(url)
            elif script == "大华 DSS 数字监控系统 attachment_clearTempFile.action SQL注入":
                result = check_dahua_dss_attachment_clearTempFile_sqli(url)
            elif script == "大华ICC智能物联综合管理平台任意文件读取":
                result = check_dahua_icc_file_read(url)
            elif script == "大华ICC智能物联综合管理平台random远程代码执行":
                result = check_dahua_icc_random_rce(url)
            elif script == "大华ICC智能物联综合管理平台 log4j远程代码执行":
                result = check_dahua_icc_log4j_rce(url)
            elif script == "大华ICC智能物联综合管理平台 fastjson远程代码执行":
                result = check_dahua_icc_fastjson_rce(url)
            elif script == "用友NC 6.5 accept.jsp任意文件上传":
                result = check_yonyou_nc_file_upload(url)
            elif script == "用友NC registerServlet JNDI 远程代码执行":
                result = check_yonyou_nc_jndi_rce(url)
            elif script == "用友NC linkVoucher SQL注入":
                result = check_yonyou_nc_linkVoucher_sqli(url)
            elif script == "用友NC showcontent SQL注入":
                result = check_yonyou_nc_showcontent_sqli(url)
            elif script == "用友NC grouptemplet 任意文件上传":
                result = check_yonyou_nc_grouptemplet_file_upload(url)
            elif script == "用友NC down/bill SQL注入":
                result = check_yonyou_nc_down_bill_sqli(url)
            elif script == "用友NC importPml SQL注入":
                result = check_yonyou_nc_importPml_sqli(url)
            elif script == "用友NC runStateServlet SQL注入":
                result = check_yonyou_nc_runStateServlet_sqli(url)
            elif script == "用友NC complainbilldetail SQL注入":
                result = check_yonyou_nc_complainbilldetail_sqli(url)
            elif script == "用友NC downTax/download SQL注入":
                result = check_yonyou_nc_downTax_download_sqli(url)
            elif script == "用友NC warningDetailInfo接口SQL注入":
                result = check_yonyou_nc_warningDetailInfo_sqli(url)
            elif script == "用友NC-Cloud importhttpscer任意文件上传":
                result = check_yonyou_nc_cloud_importhttpscer_file_upload(url)
            elif script == "用友NC-Cloud soapFormat XXE":
                result = check_yonyou_nc_cloud_soapFormat_xxe(url)
            elif script == "用友NC-Cloud IUpdateService XXE":
                result = check_yonyou_nc_cloud_IUpdateService_xxe(url)
            elif script == "用友U8 Cloud smartweb2.RPC.d XXE":
                result = check_yonyou_u8_cloud_smartweb2_rpc_xxe(url)
            elif script == "用友U8 Cloud RegisterServlet SQL注入":
                result = check_yonyou_u8_cloud_registerServlet_sqli(url)
            elif script == "用友U8-Cloud XChangeServlet XXE":
                result = check_yonyou_u8_cloud_XChangeServlet_xxe(url)
            elif script == "用友U8 Cloud MeasureQueryByToolAction SQL注入":
                result = check_yonyou_u8_cloud_MeasureQueryByToolAction_sqli(url)
            elif script == "用友GRP-U8 SmartUpload01 文件上传":
                result = check_yonyou_grp_u8_SmartUpload01_file_upload(url)
            elif script == "用友GRP-U8 userInfoWeb SQL注入致RCE":
                result = check_yonyou_grp_u8_userInfoWeb_sqli_rce(url)
            elif script == "用友GRP-U8 bx_dj_check.jsp SQL注入":
                result = check_yonyou_grp_u8_bx_dj_check_sqli(url)
            elif script == "用友GRP-U8 ufgovbank XXE":
                result = check_yonyou_grp_u8_ufgovbank_xxe(url)
            elif script == "用友GRP-U8 sqcxIndex.jsp SQL注入":
                result = check_yonyou_grp_u8_sqcxIndex_sqli(url)
            elif script == "用友GRP A++Cloud 政府财务云 任意文件读取":
                result = check_yonyou_grp_a_plus_cloud_file_read(url)
            elif script == "用友U8 CRM swfupload 任意文件上传":
                result = check_yonyou_u8_crm_swfupload_file_upload(url)
            elif script == "用友U8 CRM系统uploadfile.php接口任意文件上传":
                result = check_yonyou_u8_crm_uploadfile_file_upload(url)
            elif script == "QDocs Smart School 6.4.1 filterRecords SQL注入":
                result = check_qdocs_smart_school_sqli(url)
            elif script == "云时空社会化商业 ERP 系统 validateLoginName SQL 注入":
                result = check_yunshikong_erp_validateLoginName_sqli(url)
            elif script == "泛微E-Office json_common.php sql注入":
                result = check_fanwei_eoffice_json_common_sqli(url)
            elif script == "迪普 DPTech VPN Service 任意文件上传":
                result = check_dptech_vpn_file_upload(url)
            elif script == "畅捷通T+ getstorewarehousebystore 远程代码执行":
                result = check_tplus_getstorewarehousebystore_rce(url)
            elif script == "畅捷通T+ getdecallusers信息泄露":
                result = check_tplus_getdecallusers_info_leak(url)
            elif script == "畅捷通T+ RRATableController,Ufida.T.DI.UIP.ashx 反序列化RCE":
                result = check_tplus_RRATableController_rce(url)
            elif script == "畅捷通T+ keyEdit.aspx SQL注入":
                result = check_tplus_keyEdit_sqli(url)
            elif script == "畅捷通T+ KeyInfoList.aspx SQL注入":
                result = check_tplus_KeyInfoList_sqli(url)
            elif script == "XETUX 软件 dynamiccontent.properties.xhtml 远程代码执行":
                result = check_xetux_dynamiccontent_rce(url)
            elif script == "百卓Smart管理平台 importexport.php SQL注入":
                result = check_baizhuo_smart_importexport_sqli(url)
            self.result_text.insert(tk.END, result)
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {e}\n")
        finally:
            self.scan_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerApp(root)
    root.mainloop()
