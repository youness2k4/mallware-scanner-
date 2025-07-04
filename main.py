import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QMessageBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import platform
import nmap
from audit import system_info, network_scan, report

class ScanThread(QThread):
    update_status = pyqtSignal(str)
    update_result = pyqtSignal(str)

    def run(self):
        self.update_status.emit("Starting system info scan...")
        os_info = system_info.get_os_info()
        self.update_result.emit(f"OS Info: {os_info}\n")

        self.update_status.emit("Starting port scan on localhost...")
        try:
            open_ports = network_scan.scan_common_ports()
            if open_ports:
                self.update_result.emit(f"Open ports found: {', '.join(open_ports)}\n")
            else:
                self.update_result.emit("No open ports found on common ports.\n")
        except Exception as e:
            self.update_result.emit(f"Port scan failed: {e}\n")

        self.update_status.emit("Scan complete.")

class SecurityAuditApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Automated Security Audit Tool")
        self.setGeometry(300, 300, 600, 400)

        layout = QVBoxLayout()

        self.status_label = QLabel("Status: Ready")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)

        self.report_button = QPushButton("Generate PDF Report")
        self.report_button.clicked.connect(self.generate_pdf)
        self.report_button.setEnabled(False)
        layout.addWidget(self.report_button)

        self.setLayout(layout)

        self.scan_thread = None
        self.scan_results = ""

    def start_scan(self):
        self.result_text.clear()
        self.status_label.setText("Status: Scanning...")
        self.scan_button.setEnabled(False)
        self.report_button.setEnabled(False)

        self.scan_thread = ScanThread()
        self.scan_thread.update_status.connect(self.update_status)
        self.scan_thread.update_result.connect(self.append_result)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()

    def update_status(self, status):
        self.status_label.setText(f"Status: {status}")

    def append_result(self, text):
        self.scan_results += text
        self.result_text.append(text)

    def scan_finished(self):
        self.status_label.setText("Status: Scan complete")
        self.scan_button.setEnabled(True)
        self.report_button.setEnabled(True)

    def generate_pdf(self):
        try:
            from fpdf import FPDF
        except ImportError:
            QMessageBox.warning(self, "Missing Library", "Please install fpdf (pip install fpdf) to generate PDF reports.")
            return

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, self.scan_results)
        save_path = "security_audit_report.pdf"
        pdf.output(save_path)
        QMessageBox.information(self, "PDF Report", f"PDF report saved as {save_path}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecurityAuditApp()
    window.show()
    sys.exit(app.exec_())
