# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38472 - All system command files must be owned by root.'

control 'V-38472' do
  impact 0.5
  title 'All system command files must be owned by root.'
  desc '
System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted.
'
  tag 'stig','V-38472'
  tag severity: 'medium'
  tag checkid: 'C-46027r1_chk'
  tag fixid: 'F-43417r1_fix'
  tag version: 'RHEL-06-000048'
  tag ruleid: 'SV-50272r1_rule'
  tag fixtext: '
System executables are stored in the following directories by default:

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

If any file [FILE] in these directories is found to be owned by a user other than root, correct its ownership with the following command:

# chown root [FILE]
'
  tag checktext: '
System executables are stored in the following directories by default:

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

All files in these directories should not be group-writable or world-writable. To find system executables that are not owned by "root", run the following command for each directory [DIR] which contains system executables:

$ find -L [DIR] \! -user root


If any system executables are found to not be owned by root, this is a finding.
'

# START_DESCRIBE V-38472
  ['/bin','/usr/bin','/usr/local/bin','/sbin','/usr/sbin','/usr/local/sbin'].each do |dir|
    describe command("find -L #{dir} \! -user root") do
      its('stdout') { should eq '' }
    end
  end
# END_DESCRIBE V-38472

end
