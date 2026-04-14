import asyncio

from app.services import attack_generator


def test_generate_adversarial_prompts_backfills_to_requested_count(monkeypatch) -> None:
    monkeypatch.setattr(
        attack_generator,
        "check_easyjailbreak_dependency",
        lambda method=None: {"available": True, "reason": ""},
    )
    monkeypatch.setattr(
        attack_generator,
        "_run_real_attacker",
        lambda **_kwargs: ["pair-1", "pair-2"],
    )
    monkeypatch.setattr(
        attack_generator,
        "generate_mock_adversarial_prompts",
        lambda seed_prompt, method, count: [f"{method}-mock-{index}" for index in range(count)],
    )

    result = asyncio.run(
        attack_generator.generate_adversarial_prompts(
            seed_prompt="seed",
            method="PAIR",
            count=5,
            api_key="secret",
            model_name="gpt-5.4",
            api_base="https://api.example.test/v1",
        )
    )

    assert result["success"] is True
    assert result["generated_count"] == 5
    assert len(result["prompts"]) == 5
    assert result["generation_mode"] == "real_attacker_backfilled"
    assert "补足到 5 条" in result["note"]
