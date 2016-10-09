# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38471 - The system must forward audit records to the syslog service.'

control 'V-38471' do
  impact 0.1
  title 'The system must forward audit records to the syslog service.'
  desc '
The auditd service does not include the ability to send audit records to a centralized server for management directly.  It does, however, include an audit event multiplexor plugin (audispd) to pass audit records to the local syslog server.
'
  tag 'stig','V-38471','audit'
  tag severity: 'low'
  tag checkid: 'C-46026r1_chk'
  tag fixid: 'F-43416r1_fix'
  tag version: 'RHEL-06-000509'
  tag ruleid: 'SV-50271r1_rule'
  tag fixtext: '
Set the "active" line in "/etc/audisp/plugins.d/syslog.conf" to "yes".  Restart the auditd process.

# service auditd restart
'
  tag checktext: '
Verify the audispd plugin is active:

# grep active /etc/audisp/plugins.d/syslog.conf

If the "active" setting is missing or set to "no", this is a finding.
'

# START_DESCRIBE V-38471
  describe file('/etc/audisp/plugins.d/syslog.conf') do
    its('content') { should match "^active = yes$" }
  end
# END_DESCRIBE V-38471

end
