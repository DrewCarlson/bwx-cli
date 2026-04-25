use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn stop_agent_then_next_command_restarts_it() {
    let server = skip_if_no_vaultwarden!();

    let email = "agent@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    harness
        .run_with_stdin(&["add", "pre.stop"], b"before\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add failed");

    assert!(
        harness.run(&["stop-agent"]).status.success(),
        "stop-agent exited nonzero"
    );

    // After stop-agent, `unlock` must respawn the agent and `get` must
    // still return the entry.
    harness.check(&["unlock"]);
    assert_eq!(
        harness.check(&["get", "pre.stop"]).trim_end(),
        "before",
        "entry vanished across agent restart"
    );
}
