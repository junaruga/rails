#!/bin/sh

set +e

patch -p0 < \
    patches/rubygem-actionpack-enable-test.patch
patch -p1 < \
    patches/rubygem-actionpack-4.0.3-CVE-2014-0081-XSS-vulnerability.patch
patch -p1 < \
    patches/rubygem-actionpack-4.0.5-CVE-2014-0130-avoid-dir-traversal.patch
patch -p2 < \
    patches/rubygem-actionpack-4.1.14.1-CVE-2015-7576-fix-timing-attack-vulnerability.patch
patch -p2 < \
    patches/rubygem-actionpack-4.1.14.1-CVE-2016-0751-fix-possible-object-leak-and-denial-of-service-attack.patch
patch -p2 < \
    patches/rubygem-actionpack-4.1.14.1-CVE-2016-0752-fix-possible-information-leak-vulnerability.patch
patch -p2 < \
    patches/rubygem-actionpack-4.1.14.1-CVE-2015-7581-fix-object-leak-vulnerability-for-wildcard-controller-routes.patch
patch -p2 < \
    patches/rubygem-actionpack-4.1.14.2-CVE-2016-2097-render_data_leak_2.patch
patch -p2 < \
    patches/rubygem-actionpack-4.1.14.2-CVE-2016-2098-secure_inline_with_params.patch
