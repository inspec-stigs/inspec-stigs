# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38702 - The FTP daemon must be configured for logging or verbose mode.'

control 'V-38702' do
  impact 0.1
  title 'The FTP daemon must be configured for logging or verbose mode.'
  desc '
To trace malicious activity facilitated by the FTP service, it must be configured to ensure that all commands sent to the ftp server are logged using the verbose vsftpd log format. The default vsftpd log file is /var/log/vsftpd.log.
'
  tag 'stig','V-38702'
  tag severity: 'low'
  tag checkid: 'C-46264r1_chk'
  tag fixid: 'F-43651r1_fix'
  tag version: 'RHEL-06-000339'
  tag ruleid: 'SV-50503r1_rule'
  tag fixtext: '
Add or correct the following configuration options within the "vsftpd" configuration file, located at "/etc/vsftpd/vsftpd.conf". 

xferlog_enable=YES
xferlog_std_format=NO
log_ftp_protocol=YES
'
  tag checktext: '
Find if logging is applied to the ftp daemon. 

Procedures: 

If vsftpd is started by xinetd the following command will indicate the xinetd.d startup file. 

# grep vsftpd /etc/xinetd.d/*



# grep server_args [vsftpd xinetd.d startup file]

This will indicate the vsftpd config file used when starting through xinetd. If the [server_args]line is missing or does not include the vsftpd configuration file, then the default config file (/etc/vsftpd/vsftpd.conf) is used. 

# grep xferlog_enable [vsftpd config file]


If xferlog_enable is missing, or is not set to yes, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
