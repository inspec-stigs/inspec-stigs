# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38599 - The FTPS/FTP service on the system must be configured with the Department of Defense (DoD) login banner.'

control 'V-38599' do
  impact 0.5
  title 'The FTPS/FTP service on the system must be configured with the Department of Defense (DoD) login banner.'
  desc '
This setting will cause the system greeting banner to be used for FTP connections as well.
'
  tag 'stig','V-38599'
  tag severity: 'medium'
  tag checkid: 'C-46174r1_chk'
  tag fixid: 'F-43564r3_fix'
  tag version: 'RHEL-06-000348'
  tag ruleid: 'SV-50400r2_rule'
  tag fixtext: '
Edit the vsftpd configuration file, which resides at "/etc/vsftpd/vsftpd.conf" by default. Add or correct the following configuration options. 

banner_file=/etc/issue

Restart the vsftpd daemon.

# service vsftpd restart
'
  tag checktext: '
To verify this configuration, run the following command: 

grep "banner_file" /etc/vsftpd/vsftpd.conf

The output should show the value of "banner_file" is set to "/etc/issue", an example of which is shown below. 

# grep "banner_file" /etc/vsftpd/vsftpd.conf
banner_file=/etc/issue


If it does not, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
