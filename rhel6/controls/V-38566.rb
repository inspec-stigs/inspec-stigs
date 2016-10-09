# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38566 - The audit system must be configured to audit failed attempts to access files and programs.'

control 'V-38566' do
  impact 0.1
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc '
Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.
'
  tag 'stig','V-38566'
  tag severity: 'low'
  tag checkid: 'C-46124r1_chk'
  tag fixid: 'F-43514r2_fix'
  tag version: 'RHEL-06-000197'
  tag ruleid: 'SV-50367r2_rule'
  tag fixtext: '
At a minimum, the audit system should collect unauthorized file accesses for all users and root. Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system:

-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
-S ftruncate -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
-S ftruncate -F exit=-EPERM -F auid=0 -k access
'
  tag checktext: '
To verify that the audit system collects unauthorized file accesses, run the following commands:

# grep EACCES /etc/audit/audit.rules



# grep EPERM /etc/audit/audit.rules


If either command lacks output, this is a finding.
'

# START_DESCRIBE V-38566
  describe auditd_rules.syscall('ftruncate').action do
    it { should eq(['always']) }
  end
# END_DESCRIBE V-38566

end
