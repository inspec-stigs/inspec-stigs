# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38452 - The system package management tool must verify permissions on all files and directories associated with packages.'

control 'V-38452' do
  impact 0.1
  title 'The system package management tool must verify permissions on all files and directories associated with packages.'
  desc '
Permissions on system binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated.
'
  tag 'stig','V-38452','long','rpm'
  tag severity: 'low'
  tag checkid: 'C-46008r1_chk'
  tag fixid: 'F-43398r1_fix'
  tag version: 'RHEL-06-000518'
  tag ruleid: 'SV-50252r1_rule'
  tag fixtext: '
The RPM package management system can restore file access permissions of package files and directories. The following command will update permissions on files and directories with permissions different from what is expected by the RPM database:

# rpm --setperms [package]
'
  tag checktext: '
The following command will list which files and directories on the system have permissions different from what is expected by the RPM database:

# rpm -Va  | grep \'^.M\'

If there is any output, for each file or directory found, find the associated RPM package and compare the RPM-expected permissions with the actual permissions on the file or directory:

# rpm -qf [file or directory name]
# rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" [package] | grep  [filename]
# ls -lL [filename]

If the existing permissions are more permissive than those expected by RPM, this is a finding.
'

# START_DESCRIBE V-38452
  describe command("rpm -Va  | grep '^.M'") do
    its('stdout') { should eq '' }
  end
# END_DESCRIBE V-38452

end
