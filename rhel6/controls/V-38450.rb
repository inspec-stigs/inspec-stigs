# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38450 - The /etc/passwd file must be owned by root.'

control 'V-38450' do
  impact 0.5
  title 'The /etc/passwd file must be owned by root.'
  desc '
The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.
'
  tag 'stig','V-38450'
  tag severity: 'medium'
  tag checkid: 'C-46005r1_chk'
  tag fixid: 'F-43395r1_fix'
  tag version: 'RHEL-06-000039'
  tag ruleid: 'SV-50250r1_rule'
  tag fixtext: '
To properly set the owner of "/etc/passwd", run the command:

# chown root /etc/passwd
'
  tag checktext: '
To check the ownership of "/etc/passwd", run the command:

$ ls -l /etc/passwd

If properly configured, the output should indicate the following owner: "root"
If it does not, this is a finding.
'

# START_DESCRIBE V-38450
  describe file('/etc/passwd') do
    its('owner') { should eq 'root' }
  end
# END_DESCRIBE V-38450

end
