package com.company

import java.net.InetAddress
import java.net.UnknownHostException
import kotlin.experimental.and

/**
 * The class should identify IP's, arriving from a given CDIR.
 */
class IpAddressValidator(ip: String) {
    private var maskBits = 0
    private val blacklistedCidr: InetAddress

    fun isAllowed(incomingIp: String): Boolean {
        val remoteAddress = parseAddress(incomingIp)
        if (blacklistedCidr.javaClass != remoteAddress.javaClass) {
            return true
        }
        if (maskBits < 0) {
            return remoteAddress != blacklistedCidr
        }
        val removeAddr = remoteAddress.address
        val blacklistAddr = blacklistedCidr.address
        val maskFullBytes = maskBits / 8
        val finalByte = (0xFF00 shr (maskBits and 0x07)).toByte()
        for (i in 0 until maskFullBytes) {
            if (removeAddr[i] != blacklistAddr[i]) {
                return true
            }
        }
        return if (finalByte.toInt() != 0) {
            removeAddr[maskFullBytes] and finalByte != blacklistAddr[maskFullBytes] and finalByte
        } else false
    }

    private fun parseAddress(address: String): InetAddress {
        return try {
            InetAddress.getByName(address)
        } catch (e: UnknownHostException) {
            throw IllegalArgumentException("Failed to parse address$address", e)
        }
    }

    /**
     * @param ip that should be validated
     * come.
     */
    init {
        var ip = ip
        if (ip.indexOf('/') > 0) {
            val addressAndMask = ip.split("/".toRegex()).toTypedArray()
            ip = addressAndMask[0]
            maskBits = addressAndMask[1].toInt()
        } else {
            maskBits = -1
        }
        blacklistedCidr = parseAddress(ip)
        assert(blacklistedCidr.address.size * 8 >= maskBits) {
            String.format(
                "IP address %s is too short for bitmask of length %d",
                ip, maskBits
            )
        }
    }
}