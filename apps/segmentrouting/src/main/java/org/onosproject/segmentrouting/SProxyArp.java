package org.onosproject.segmentrouting;

import org.apache.felix.scr.annotations.*;
import org.onlab.packet.Ethernet;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.flow.*;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flow.instructions.L2ModificationInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction;
import org.osgi.service.component.ComponentContext;

import java.util.List;

import static jdk.nashorn.internal.runtime.regexp.joni.Config.log;

@Component(immediate = true)
public class SProxyArp {

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    protected ComponentConfigService cfgService;


    private ApplicationId appId;
    private CoreService coreService;

    @Activate
    public void activate(ComponentContext context) {
        cfgService.registerProperties(getClass());
        appId = coreService.registerApplication("org.onosproject.sproxyarp");
        
        // Begin SProxyArp rule creation

        // Rule for h1

        // Traffic Selector
        TrafficSelector.Builder trafficSelector = DefaultTrafficSelector.builder();
        trafficSelector.matchEthType(Ethernet.TYPE_ARP);
        trafficSelector.matchArpTpa(Ip4Address.valueOf("10.0.0.1"));
        trafficSelector.matchArpOp(1);

        // Traffic Treatment (Instructions)
        TrafficTreatment.Builder trafficTreatment = DefaultTrafficTreatment.builder();
        Instruction ethDestInstruction = new L2ModificationInstruction.ModEtherInstruction(L2ModificationInstruction.L2SubType.ETH_DST, MacAddress.BROADCAST);
        Instruction ethSrcInstruction = new L2ModificationInstruction.ModEtherInstruction(L2ModificationInstruction.L2SubType.ETH_DST, MacAddress.valueOf("00:00:00:00:00:01"));
        Instruction arpOpInstruction = new L3ModificationInstruction.ModArpOpInstruction(L3ModificationInstruction.L3SubType.ARP_OP, (short) 2);
        Instruction arpShaInstruction = new L3ModificationInstruction.ModArpEthInstruction(L3ModificationInstruction.L3SubType.ARP_SHA, MacAddress.valueOf("00:00:00:00:00:01"));
        Instruction arpSpaInstruction = new L3ModificationInstruction.ModArpIPInstruction()L3ModificationInstruction.L3SubType.ARP_SPA, Ip4Address.valueOf("10.0.0.1");
        Instruction arpThaInstruction = new L3ModificationInstruction.ModArpEthInstruction(L3ModificationInstruction.L3SubType.ARP_SHA, MacAddress.BROADCAST);

        //TODO: ARP_TPA not part of enum, try IPV4_DST
        Instruction arpTpaInstruction = new L3ModificationInstruction.ModArpIPInstruction()L3ModificationInstruction.L3SubType.ARP_SPA, Ip4Address.valueOf("10.255.255.255");
        trafficTreatment.add();
    }

    @Deactivate
    public void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        flowRuleService.removeFlowRulesById(appId);
    }
    
}
