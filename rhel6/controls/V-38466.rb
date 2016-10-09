# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38466 - Library files must be owned by root.'

control 'V-38466' do
  impact 0.5
  title 'Library files must be owned by root.'
  desc '
Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Proper ownership is necessary to protect the integrity of the system.
'
  tag 'stig','V-38466','lib'
  tag severity: 'medium'
  tag checkid: 'C-46021r1_chk'
  tag fixid: 'F-43411r1_fix'
  tag version: 'RHEL-06-000046'
  tag ruleid: 'SV-50266r1_rule'
  tag fixtext: '
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:

/lib
/lib64
/usr/lib
/usr/lib64

If any file in these directories is found to be owned by a user other than root, correct its ownership with the following command:

# chown root [FILE]
'
  tag checktext: '
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:

/lib
/lib64
/usr/lib
/usr/lib64


Kernel modules, which can be added to the kernel during runtime, are stored in "/lib/modules". All files in these directories should not be group-writable or world-writable.  To find shared libraries that are not owned by "root", run the following command for each directory [DIR] which contains shared libraries:

$ find -L [DIR] \! -user root


If any of these files are not owned by root, this is a finding.
'

# START_DESCRIBE V-38466
  ['/lib','/lib64','/usr/lib','/usr/lib64'].each do |lib|
    describe command("find -L #{lib} \! -user root") do
      its('stdout') { should eq '' }
    end
  end
# END_DESCRIBE V-38466

end
