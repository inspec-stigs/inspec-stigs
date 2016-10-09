# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38568 - The audit system must be configured to audit successful file system mounts.'

control 'V-38568' do
  impact 0.1
  title 'The audit system must be configured to audit successful file system mounts.'
  desc '
The unauthorized exportation of data to external media could result in an information leak where classified information, Privacy Act information, and intellectual property could be lost. An audit trail should be created each time a filesystem is mounted to help identify and guard against information loss.
'
  tag 'stig','V-38568'
  tag severity: 'low'
  tag checkid: 'C-46126r2_chk'
  tag fixid: 'F-43516r2_fix'
  tag version: 'RHEL-06-000199'
  tag ruleid: 'SV-50369r3_rule'
  tag fixtext: '
At a minimum, the audit system should collect media exportation events for all users and root. Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system:

-a always,exit -F arch=ARCH -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=ARCH -S mount -F auid=0 -k export
'
  tag checktext: '
To verify that auditing is configured for all media exportation events, run the following command:

$ sudo grep -w "mount" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines.

If no line is returned, this is a finding.
'

# START_DESCRIBE V-38568
  describe auditd_rules.syscall('mount').action do
    it { should eq(['always']) }
  end
# END_DESCRIBE V-38568

end
