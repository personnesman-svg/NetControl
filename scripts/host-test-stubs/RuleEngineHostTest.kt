import com.netcontrol.app.data.RuleEntity
import com.netcontrol.app.network.FlowFacts
import com.netcontrol.app.network.RuleAction
import com.netcontrol.app.network.RuleEngine

private fun rule(
    id: Long,
    priority: Int = 100,
    action: String = "BLOCK",
    protocol: String = "ANY",
    ip: String = "",
    port: Int? = null,
    uid: Int? = null,
    domain: String = "",
    enabled: Boolean = true,
) = RuleEntity(id, priority, "rule-$id", enabled, action, protocol, ip, port, uid, domain)

private fun facts(
    ip: String = "203.0.113.7",
    protocol: String = "TCP",
    port: Int? = 443,
    uid: Int? = null,
    domain: String? = "api.example.com",
) = FlowFacts(protocol, ip, port, uid, domain)

fun main() {
    check(RuleEngine.evaluate(listOf(rule(2, priority = 20), rule(1, priority = 10, action = "ALLOW")), facts()).action == RuleAction.ALLOW)
    check(RuleEngine.evaluate(listOf(rule(1, enabled = false)), facts()).action == RuleAction.OBSERVE)
    check(RuleEngine.evaluate(listOf(rule(1, domain = "EXAMPLE.COM")), facts()).action == RuleAction.BLOCK)
    check(RuleEngine.evaluate(listOf(rule(1, domain = "example.com")), facts(domain = "example.com.attacker.test")).action == RuleAction.OBSERVE)
    check(RuleEngine.evaluate(listOf(rule(1, domain = "example.com")), facts(domain = null)).action == RuleAction.OBSERVE)
    check(RuleEngine.evaluate(listOf(rule(1, uid = 1234)), facts(uid = null)).action == RuleAction.OBSERVE)
    check(RuleEngine.evaluate(listOf(rule(1, ip = "2001:db8::1")), facts(ip = "2001:0db8:0:0:0:0:0:1", domain = null)).action == RuleAction.BLOCK)
    check(RuleEngine.evaluate(listOf(rule(1, ip = "not-an-ip")), facts(domain = null)).action == RuleAction.OBSERVE)
    check(RuleEngine.evaluate(listOf(rule(1, protocol = "UDP")), facts(protocol = "TCP")).action == RuleAction.OBSERVE)
    println("PASS: ordered rules, disabled rules, domain boundaries/unknowns, UID unknowns, IPv6 canonicalization and malformed IP safety")
}
