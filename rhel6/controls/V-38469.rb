# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38469 - All system command files must have mode 755 or less permissive.'

control 'V-38469' do
  impact 0.5
  title 'All system command files must have mode 755 or less permissive.'
  desc '
System binaries are executed by privileged users, as well as system services, and restrictive permissions are necessary to ensure execution of these programs cannot be co-opted.
'
  tag 'stig','V-38469','bin'
  tag severity: 'medium'
  tag checkid: 'C-46024r3_chk'
  tag fixid: 'F-43414r1_fix'
  tag version: 'RHEL-06-000047'
  tag ruleid: 'SV-50269r3_rule'
  tag fixtext: '
System executables are stored in the following directories by default:

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

If any file in these directories is found to be group-writable or world-writable, correct its permission with the following command:

# chmod go-w [FILE]
'
  tag checktext: '
System executables are stored in the following directories by default:

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

All files in these directories should not be group-writable or world-writable. To find system executables that are group-writable or world-writable, run the following command for each directory [DIR] which contains system executables:

$ find -L [DIR] -perm /022 -type f

If any system executables are found to be group-writable or world-writable, this is a finding.
'

# START_DESCRIBE V-38469
  ['/bin','/usr/bin','/usr/local/bin','/sbin','/usr/sbin','/usr/local/sbin'].each do |dir|
    describe command("find -L #{dir} -perm /022 -type f") do
      its('stdout') { should eq '' }
    end
  end
# END_DESCRIBE V-38469

end
