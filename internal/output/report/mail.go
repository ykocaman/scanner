package report

import (
	"fmt"
	"net/smtp"

	"github.com/ykocaman/scanner/internal/config"
)

const mailBodyTemplate = "From: %s\r\n" +
	"To: %s\r\n" +
	"Subject: Vulnerability Report [%d]\r\n" +
	"MIME-version: 1.0;\r\n" +
	"Content-Type: text/html; charset=\"UTF-8\";\r\n\r\n" +
	`<style>
		table {border-collapse: collapse;}
		td {padding: 10px;border: 1px solid black}
		th {padding: 10px;border: 1px solid black}
		tfoot {font-weight: bold; color: red}
	</style>` + "\n%s"

// SendMail emails an HTML report body summarizing affectedTotal findings,
// using the SMTP settings in cfg.
func SendMail(cfg config.Config, htmlBody string, affectedTotal int) error {
	msg := fmt.Sprintf(mailBodyTemplate, cfg.MailUsername, cfg.MailTo, affectedTotal, htmlBody)

	addr := fmt.Sprintf("%s:%s", cfg.MailServerHost, cfg.MailServerPort)
	auth := smtp.PlainAuth("", cfg.MailUsername, cfg.MailPassword, cfg.MailServerHost)

	return smtp.SendMail(addr, auth, cfg.MailUsername, []string{cfg.MailTo}, []byte(msg))
}
