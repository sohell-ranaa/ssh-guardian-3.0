/**
 * SSH Guardian v3.0 - Simulation Index
 * Namespace setup and global exports for backward compatibility
 */
(function() {
    'use strict';

    // Initialize namespace
    window.Sim = window.Sim || {};

    // Global exports for backward compatibility
    // These map old function names to new namespace
    window.openScenarioModal = (id) => Sim.Modal.open(id);
    window.closeScenarioModal = () => Sim.Modal.close();
    window.runScenarioAction = (type) => Sim.Runner.run(type);
    window.runDemoScenario = (id) => Sim.Runner.runDemoScenario(id);
    window.showLiveStatus = (...args) => Sim.LiveStatus.show(...args);
    window.hideLiveStatus = () => Sim.LiveStatus.hide();
    window.updateLiveStep = (step, status) => Sim.LiveStatus.updateStep(step, status);
    window.addLiveLog = (msg, type) => Sim.LiveStatus.addLog(msg, type);
    window.showSimulationResults = (data) => Sim.Results.show(data);
    window.hideSimulationResults = () => Sim.Results.hide();
    window.populateAnalysisTab = (data) => Sim.Analysis.populate(data);
    window.populateResultsTab = (data) => Sim.Recommendations.populate(data);
    window.blockIPWithModal = (ip) => Sim.Blocking.showModal(ip);
    window.blockIPInline = (ip) => Sim.Blocking.showModal(ip);
    window.executeIPBlock = (ip) => Sim.Blocking.execute(ip);
    window.copyToClipboard = (text, label) => Sim.Utils.copyToClipboard(text, label);

    console.log('[Simulation] Module initialized');
})();
