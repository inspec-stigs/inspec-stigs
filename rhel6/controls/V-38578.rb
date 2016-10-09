# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38578 - The audit system must be configured to audit changes to the /etc/sudoers file.'

control 'V-38578' do
  impact 0.1
  title 'The audit system must be configured to audit changes to the /etc/sudoers file.'
  desc '
The actions taken by system administrators should be audited to keep a record of what was executed on the system, as well as, for accountability purposes.
'
  tag 'stig','V-38578'
  tag severity: 'low'
  tag checkid: 'C-46136r1_chk'
  tag fixid: 'F-43526r1_fix'
  tag version: 'RHEL-06-000201'
  tag ruleid: 'SV-50379r1_rule'
  tag fixtext: '
At a minimum, the audit system should collect administrator actions for all users and root. Add the following to "/etc/audit/audit.rules":

-w /etc/sudoers -p wa -k actions
'
  tag checktext: '
To verify that auditing is configured for system administrator actions, run the following command:

# auditctl -l | grep "watch=/etc/sudoers"


If there is no output, this is a finding.
'

# START_DESCRIBE V-38578
  describe auditd_rules do
    its('lines') { should include("-w /etc/sudoers -p wa -k actions") }
  end
# END_DESCRIBE V-38578

end
