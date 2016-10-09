# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38663 - The system package management tool must verify permissions on all files and directories associated with the audit package.'

control 'V-38663' do
  impact 0.5
  title 'The system package management tool must verify permissions on all files and directories associated with the audit package.'
  desc '
Permissions on audit binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated.
'
  tag 'stig','V-38663'
  tag severity: 'medium'
  tag checkid: 'C-46223r1_chk'
  tag fixid: 'F-43612r1_fix'
  tag version: 'RHEL-06-000278'
  tag ruleid: 'SV-50464r1_rule'
  tag fixtext: '
The RPM package management system can restore file access permissions of the audit package files and directories. The following command will update audit files with permissions different from what is expected by the RPM database:

# rpm --setperms audit
'
  tag checktext: '
The following command will list which audit files on the system have permissions different from what is expected by the RPM database:

# rpm -V audit | grep \'^.M\'

If there is any output, for each file or directory found, compare the RPM-expected permissions with the permissions on the file or directory:

# rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" audit | grep  [filename]
# ls -lL [filename]

If the existing permissions are more permissive than those expected by RPM, this is a finding.
'

# START_DESCRIBE V-38663
  tag 'rpm','permissions'
  describe command("rpm -V audit | grep '^.M'") do
    its('stdout') { should eq "" }
  end
# END_DESCRIBE V-38663

end
