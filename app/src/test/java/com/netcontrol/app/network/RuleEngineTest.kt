package com.netcontrol.app.network

import com.netcontrol.app.data.RuleEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RuleEngineTest {
    private val flow = FlowFacts(protocol = "TCP", destinationIp = "203.0.113.7", destinationPort = 443, uid = 10234, domain = "example.com")

    @Test fun firstMatchingPriorityWins() {
        val later = RuleEntity(id = 2, priority = 20, name = "observe", action = "OBSERVE", protocol = "ANY")
        val earlier = RuleEntity(id = 1, priority = 10, name = "block TLS", action = "BLOCK", protocol = "TCP", port = 443)
        val result = RuleEngine.evaluate(listOf(later, earlier), flow)
        assertEquals(RuleAction.BLOCK, result.action)
        assertEquals(1L, result.matchedRuleId)
    }

    @Test fun disabledRuleDoesNotMatch() {
        val disabled = RuleEntity(id = 1, name = "off", action = "BLOCK", enabled = false, destinationIp = flow.destinationIp)
        val result = RuleEngine.evaluate(listOf(disabled), flow)
        assertEquals(RuleAction.OBSERVE, result.action)
        assertNull(result.matchedRuleId)
    }

    @Test fun domainMatchIsCaseInsensitiveAndUidMustMatch() {
        val matching = RuleEntity(id = 1, name = "domain", action = "ALLOW", domain = "EXAMPLE.COM", uid = 10234)
        assertEquals(RuleAction.ALLOW, RuleEngine.evaluate(listOf(matching), flow).action)
        val wrongUid = matching.copy(uid = 2000)
        assertEquals(RuleAction.OBSERVE, RuleEngine.evaluate(listOf(wrongUid), flow).action)
    }

    @Test fun domainRuleMatchesSubdomainsButNotLookalikes() {
        val domainRule = RuleEntity(id = 3, name = "block site", action = "BLOCK", domain = "example.com")
        assertEquals(RuleAction.BLOCK, RuleEngine.evaluate(listOf(domainRule), flow.copy(domain = "www.example.com")).action)
        assertEquals(RuleAction.BLOCK, RuleEngine.evaluate(listOf(domainRule), flow.copy(domain = "example.com.")).action)
        assertEquals(RuleAction.OBSERVE, RuleEngine.evaluate(listOf(domainRule), flow.copy(domain = "example.com.attacker.test")).action)
    }

    @Test fun unknownDomainDoesNotSatisfyDomainRule() {
        val rule = RuleEntity(id = 4, name = "block domain", action = "BLOCK", domain = "example.com")
        assertEquals(RuleAction.OBSERVE, RuleEngine.evaluate(listOf(rule), flow.copy(domain = null)).action)
        assertEquals(RuleAction.OBSERVE, RuleEngine.evaluate(listOf(rule), flow.copy(domain = "")).action)
    }

    @Test fun equivalentIpv6LiteralsMatchByAddressBytes() {
        val rule = RuleEntity(id = 5, name = "ipv6", action = "BLOCK", destinationIp = "2001:db8::1")
        val ipv6Flow = flow.copy(destinationIp = "2001:0db8:0000:0000:0000:0000:0000:0001", domain = null)
        assertEquals(RuleAction.BLOCK, RuleEngine.evaluate(listOf(rule), ipv6Flow).action)
    }

    @Test fun ipRuleDoesNotMatchUnknownOrMalformedAddress() {
        val rule = RuleEntity(id = 6, name = "ip", action = "BLOCK", destinationIp = "203.0.113.7")
        assertEquals(RuleAction.OBSERVE, RuleEngine.evaluate(listOf(rule), flow.copy(destinationIp = "")).action)
        assertEquals(RuleAction.OBSERVE, RuleEngine.evaluate(listOf(rule), flow.copy(destinationIp = "domain.example")).action)
    }
}
