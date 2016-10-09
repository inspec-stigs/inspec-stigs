# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38465 - Library files must have mode 0755 or less permissive.'

control 'V-38465' do
  impact 0.5
  title 'Library files must have mode 0755 or less permissive.'
  desc '
Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Restrictive permissions are necessary to protect the integrity of the system.
'
  tag 'stig','V-38465','lib'
  tag severity: 'medium'
  tag checkid: 'C-46019r4_chk'
  tag fixid: 'F-43409r2_fix'
  tag version: 'RHEL-06-000045'
  tag ruleid: 'SV-50265r3_rule'
  tag fixtext: '
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:

/lib
/lib64
/usr/lib
/usr/lib64

If any file in these directories is found to be group-writable or world-writable, correct its permission with the following command:

# chmod go-w [FILE]
'
  tag checktext: '
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:

/lib
/lib64
/usr/lib
/usr/lib64


Kernel modules, which can be added to the kernel during runtime, are stored in "/lib/modules". All files in these directories should not be group-writable or world-writable. To find shared libraries that are group-writable or world-writable, run the following command for each directory [DIR] which contains shared libraries:

$ find -L [DIR] -perm /022 -type f


If any of these files (excluding broken symlinks) are group-writable or world-writable, this is a finding.
'

# START_DESCRIBE V-38465
  ['/lib','/lib64','/usr/lib','/usr/lib64'].each do |lib|
    describe command("find -L #{lib} -perm /022 -type f") do
      its('stdout') { should eq '' }
    end
  end
# END_DESCRIBE V-38465

end
