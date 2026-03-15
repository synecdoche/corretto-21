/*
 * Copyright (c) 2001, 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <arpa/inet.h>

#if defined(__linux__) || defined(_ALLBSD_SOURCE)
#include <netinet/in.h>
#endif

#include "jni.h"
#include "jni_util.h"
#include "jlong.h"
#include "net_util.h"
#include "nio.h"
#include "nio_util.h"

#include "sun_nio_ch_DatagramChannelImpl.h"

JNIEXPORT void JNICALL
Java_sun_nio_ch_DatagramChannelImpl_disconnect0(JNIEnv *env, jclass clazz,
                                                jobject fdo, jboolean isIPv6)
{
    jint fd = fdval(env, fdo);
    int rv;

#if defined(__APPLE__)
    // On macOS systems we use disconnectx
    rv = disconnectx(fd, SAE_ASSOCID_ANY, SAE_CONNID_ANY);
#else
    SOCKETADDRESS sa;
    memset(&sa, 0, sizeof(sa));
    #if defined(_ALLBSD_SOURCE)
        sa.sa.sa_family = isIPv6 ? AF_INET6 : AF_INET;
    #else
        sa.sa.sa_family = AF_UNSPEC;
    #endif
    socklen_t len = isIPv6 ? sizeof(struct sockaddr_in6) :
                             sizeof(struct sockaddr_in);
    rv = connect(fd, &sa.sa, len);
#endif

#if defined(_ALLBSD_SOURCE) && !defined(__APPLE__)
    // On _ALLBSD_SOURCE except __APPLE__ we consider EADDRNOTAVAIL
    // error to be OK and ignore it. __APPLE__ systems are excluded
    // in this check since for __APPLE__ systems, unlike other BSD systems,
    // we issue a "disconnectx" call (a few lines above),
    // which isn't expected to return this error code.
    if (rv < 0 && errno == EADDRNOTAVAIL)
        rv = errno = 0;
#elif defined(_AIX)
    /* See W. Richard Stevens, "UNIX Network Programming, Volume 1", p. 254:
     * 'Setting the address family to AF_UNSPEC might return EAFNOSUPPORT
     * but that is acceptable.
     */
    if (rv < 0 && errno == EAFNOSUPPORT)
        rv = errno = 0;
#endif // defined(_ALLBSD_SOURCE) || defined(_AIX)

    if (rv < 0)
        handleSocketError(env, errno);
}

JNIEXPORT jint JNICALL
Java_sun_nio_ch_DatagramChannelImpl_receive0(JNIEnv *env, jclass clazz,
                                             jobject fdo, jlong bufAddress,
                                             jint len, jlong senderAddress,
                                             jboolean connected)
{
    jint fd = fdval(env, fdo);
    void *buf = (void *)jlong_to_ptr(bufAddress);
    SOCKETADDRESS *sa = (SOCKETADDRESS *)jlong_to_ptr(senderAddress);
    socklen_t sa_len = sizeof(SOCKETADDRESS);
    jboolean retry = JNI_FALSE;
    jint n;

    if (len > MAX_PACKET_LEN) {
        len = MAX_PACKET_LEN;
    }

    do {
        retry = JNI_FALSE;
        n = recvfrom(fd, buf, len, 0, (struct sockaddr *)sa, &sa_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return IOS_UNAVAILABLE;
            }
            if (errno == EINTR) {
                return IOS_INTERRUPTED;
            }
            if (errno == ECONNREFUSED) {
                if (connected == JNI_FALSE) {
                    retry = JNI_TRUE;
                } else {
                    JNU_ThrowByName(env, JNU_JAVANETPKG "PortUnreachableException", 0);
                    return IOS_THROWN;
                }
            } else {
                return handleSocketError(env, errno);
            }
        }
    } while (retry == JNI_TRUE);

    return n;
}

JNIEXPORT jint JNICALL
Java_sun_nio_ch_DatagramChannelImpl_send0(JNIEnv *env, jclass clazz,
                                          jobject fdo, jlong bufAddress, jint len,
                                          jlong targetAddress, jint targetAddressLen)
{
    jint fd = fdval(env, fdo);
    void *buf = (void *)jlong_to_ptr(bufAddress);
    SOCKETADDRESS *sa = (SOCKETADDRESS *)jlong_to_ptr(targetAddress);
    socklen_t sa_len = (socklen_t) targetAddressLen;
    jint n;
    struct sockaddr* skadr = (struct sockaddr*) sa;
    char sb[INET6_ADDRSTRLEN > INET_ADDRSTRLEN ? INET6_ADDRSTRLEN : INET_ADDRSTRLEN];
    /* char sb[INET_ADDRSTRLEN] = '\0'; */
    /* char sb6[INET6_ADDRSTRLEN] = '\0'; */

    if (len > MAX_PACKET_LEN) {
        len = MAX_PACKET_LEN;
    }

    fprintf(stderr, "FNORD: len: %d; targetAddressLen: %d\n", len, targetAddressLen);
    switch(skadr->sa_family) {
    case AF_INET: {
        sb[INET_ADDRSTRLEN] = '\0';
        struct sockaddr_in* addr_in = (struct sockaddr_in *) sa;
        inet_ntop(AF_INET, &(addr_in->sin_addr), sb, INET_ADDRSTRLEN);
        fprintf(stderr, "  IPV4 addr: %s\n", sb);
        break;
    }
    case AF_INET6: {
        sb[INET6_ADDRSTRLEN] = '\0';
        struct sockaddr_in6* addr_in = (struct sockaddr_in6 *) sa;
        inet_ntop(AF_INET6, &(addr_in->sin6_addr), sb, INET6_ADDRSTRLEN);
        fprintf(stderr, "  IPV6 addr: %s\n", sb);
        break;
    }
    }

    n = sendto(fd, buf, len, 0, (struct sockaddr *)sa, sa_len);
    if (n < 0) {
        fprintf(stderr, "  ! got error: %s\n", strerror(errno));
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return IOS_UNAVAILABLE;
        }
        if (errno == EINTR) {
            return IOS_INTERRUPTED;
        }
        if (errno == ECONNREFUSED) {
            JNU_ThrowByName(env, JNU_JAVANETPKG "PortUnreachableException", 0);
            return IOS_THROWN;
        }
        return handleSocketError(env, errno);
    }
    return n;
}
