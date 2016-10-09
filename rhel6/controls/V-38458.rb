# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38458 - The /etc/group file must be owned by root.'

control 'V-38458' do
  impact 0.5
  title 'The /etc/group file must be owned by root.'
  desc '
The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.
'
  tag 'stig','V-38458'
  tag severity: 'medium'
  tag checkid: 'C-46013r1_chk'
  tag fixid: 'F-43403r1_fix'
  tag version: 'RHEL-06-000042'
  tag ruleid: 'SV-50258r1_rule'
  tag fixtext: '
To properly set the owner of "/etc/group", run the command:

# chown root /etc/group
'
  tag checktext: '
To check the ownership of "/etc/group", run the command:

$ ls -l /etc/group

If properly configured, the output should indicate the following owner: "root"
If it does not, this is a finding.
'

# START_DESCRIBE V-38458
  describe file('/etc/group') do
    its('group') { should eq 'root' }
  end
# END_DESCRIBE V-38458

end
