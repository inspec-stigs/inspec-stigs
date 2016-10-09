# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38619 - There must be no .netrc files on the system.'

control 'V-38619' do
  impact 0.5
  title 'There must be no .netrc files on the system.'
  desc '
Unencrypted passwords for remote FTP servers may be stored in ".netrc" files. DoD policy requires passwords be encrypted in storage and not used in access scripts.
'
  tag 'stig','V-38619'
  tag severity: 'medium'
  tag checkid: 'C-46179r3_chk'
  tag fixid: 'F-43569r2_fix'
  tag version: 'RHEL-06-000347'
  tag ruleid: 'SV-50420r2_rule'
  tag fixtext: '
The ".netrc" files contain logon information used to auto-logon into FTP servers and reside in the user\'s home directory. These files may contain unencrypted passwords to remote FTP servers making them susceptible to access by unauthorized users and should not be used. Any ".netrc" files should be removed.
'
  tag checktext: '
To check the system for the existence of any ".netrc" files, run the following command:

$ sudo find /root /home -xdev -name .netrc

If any .netrc files exist, this is a finding.
'

# START_DESCRIBE V-38619
  tag '.netrc'
  describe command('find /root /home -xdev -name .netrc') do
    its('stdout') { should eq "" }
  end
# END_DESCRIBE V-38619

end
