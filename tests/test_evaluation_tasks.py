import asyncio
import json
import sqlite3
from pathlib import Path

from app.models import EvaluationCreateRequest
from app.services import evaluation_tasks


def _create_legacy_eval_db(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE evaluation_tasks (
                task_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                cancel_requested_at TEXT,
                dataset_id TEXT NOT NULL,
                attack_category TEXT NOT NULL,
                requested_sample_count INTEGER,
                category_total_count INTEGER,
                prompts_count INTEGER,
                total INTEGER NOT NULL DEFAULT 0,
                completed INTEGER NOT NULL DEFAULT 0,
                success_count INTEGER NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                error_count INTEGER NOT NULL DEFAULT 0,
                request_payload TEXT NOT NULL,
                config_snapshot TEXT NOT NULL,
                error_code TEXT,
                error_message TEXT
            );

            CREATE TABLE evaluation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                result_index INTEGER NOT NULL,
                phase TEXT NOT NULL,
                prompt TEXT NOT NULL,
                target_type TEXT NOT NULL,
                eval_type TEXT NOT NULL,
                response_content TEXT NOT NULL,
                is_success INTEGER NOT NULL,
                latency REAL NOT NULL,
                reasoning_trace TEXT NOT NULL,
                evaluator_version TEXT NOT NULL,
                model_name TEXT NOT NULL,
                status TEXT NOT NULL,
                error_code TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(task_id) REFERENCES evaluation_tasks(task_id)
            );

            CREATE INDEX idx_eval_results_task_idx
            ON evaluation_results(task_id, result_index);
            """
        )
        conn.commit()
    finally:
        conn.close()


def test_init_evaluation_store_migrates_legacy_results_table(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "legacy_eval.db"
    _create_legacy_eval_db(db_path)
    monkeypatch.setattr(evaluation_tasks, "JB_DEMO_EVAL_DB_PATH", db_path)

    asyncio.run(evaluation_tasks.init_evaluation_store())

    conn = sqlite3.connect(str(db_path))
    try:
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(evaluation_results)").fetchall()
        }
        indexes = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'evaluation_results'"
            ).fetchall()
        }
    finally:
        conn.close()

    assert {"seed_prompt", "source_attack_category", "attack_method", "generation_mode"} <= columns
    assert {"idx_eval_results_task_method", "idx_eval_results_task_category"} <= indexes


def test_multi_attack_evaluation_summary_and_export(tmp_path, monkeypatch) -> None:
    db_path = tmp_path / "evaluation_tasks.db"
    monkeypatch.setattr(evaluation_tasks, "JB_DEMO_EVAL_DB_PATH", db_path)

    dataset_entries = [
        {
            "row_id": 1,
            "prompt": "seed harmful prompt",
            "attack_category": "roleplay_persona",
        }
    ]

    async def fake_generate(seed_prompt: str, method: str, count: int, **_: str):
        return {
            "success": True,
            "method": method,
            "seed_prompt": seed_prompt,
            "generated_count": count,
            "generation_mode": "real_attacker",
            "prompts": [
                {
                    "id": idx,
                    "prompt": f"{method}:{seed_prompt}:{idx}",
                    "technique": method,
                }
                for idx in range(count)
            ],
        }

    async def fake_evaluate(prompt: str, target: str, evaluator: str):
        success = target == "api" and prompt.endswith(":0")
        return {
            "prompt": prompt,
            "target_type": target,
            "eval_type": evaluator,
            "response_content": f"response for {prompt}",
            "is_success": success,
            "latency": 0.12,
            "reasoning_trace": "ok",
            "evaluator_version": "keyword_test_v1",
            "model_name": f"model-{target}",
            "status": "ok",
            "error_code": "",
            "error_message": "",
        }

    monkeypatch.setattr(evaluation_tasks, "load_dataset_entries", lambda *_args, **_kwargs: dataset_entries)
    monkeypatch.setattr(evaluation_tasks, "generate_adversarial_prompts", fake_generate)
    monkeypatch.setattr(evaluation_tasks, "evaluate_single_prompt", fake_evaluate)

    async def runner() -> None:
        await evaluation_tasks.init_evaluation_store()

        created = await evaluation_tasks.create_evaluation_task(
            EvaluationCreateRequest(
                dataset_id="harmbench_text_test",
                attack_category="roleplay_persona",
                sample_count=1,
                target="api",
                evaluator="keyword",
                attack_methods=["PAIR", "TAP"],
                generated_prompt_count_per_seed=2,
                include_guardrail=True,
                guardrail_target="local",
                guardrail_evaluator="keyword",
            )
        )

        task_id = created["task_id"]
        task = {}
        for _ in range(200):
            task = await evaluation_tasks.get_evaluation_task(task_id)
            if task["status"] in {"completed", "failed", "cancelled"}:
                break
            await asyncio.sleep(0.02)

        assert task["status"] == "completed"
        assert task["summary"]["total"] == 8
        assert task["summary"]["completed"] == 8
        assert task["summary_metrics"]["samples_evaluated"] == 4
        assert task["summary_metrics"]["attack_method_count"] == 2
        assert task["summary_metrics"]["attack_category_count"] == 1
        assert [item["key"] for item in task["by_attack_method"]] == ["PAIR", "TAP"]
        assert [item["rank"] for item in task["by_attack_method"]] == [1, 2]

        phase_summary = task["phase_summary"]
        assert phase_summary["red_team"]["total"] == 4
        assert phase_summary["red_team"]["attack_success_count"] == 2
        assert phase_summary["guardrail"]["total"] == 4
        assert phase_summary["guardrail"]["blocked_count"] == 4

        results_payload = await evaluation_tasks.get_evaluation_results(task_id, offset=0, limit=20)
        assert results_payload["total_results"] == 8
        assert results_payload["results"][0]["seed_prompt"] == "seed harmful prompt"
        assert results_payload["results"][0]["source_attack_category"] == "roleplay_persona"
        assert results_payload["results"][0]["attack_method"] in {"PAIR", "TAP"}
        assert results_payload["results"][0]["generation_mode"] == "real_attacker"

        exported_json = await evaluation_tasks.export_evaluation_results(task_id, "json")
        json_payload = json.loads(exported_json["content"].decode("utf-8"))
        assert json_payload["summary_metrics"]["attack_method_count"] == 2
        assert len(json_payload["results"]) == 8

        exported_csv = await evaluation_tasks.export_evaluation_results(task_id, "csv")
        csv_text = exported_csv["content"].decode("utf-8")
        assert "attack_method" in csv_text
        assert "source_attack_category" in csv_text

        exported_md = await evaluation_tasks.export_evaluation_results(task_id, "markdown")
        md_text = exported_md["content"].decode("utf-8")
        assert "## By Attack Method" in md_text
        assert "| PAIR |" in md_text
        assert "| TAP |" in md_text

        created_direct = await evaluation_tasks.create_evaluation_task(
            EvaluationCreateRequest(
                dataset_id="harmbench_text_test",
                attack_category="roleplay_persona",
                sample_count=1,
                target="api",
                evaluator="keyword",
                include_guardrail=False,
            )
        )
        direct_task_id = created_direct["task_id"]
        direct_task = {}
        for _ in range(200):
            direct_task = await evaluation_tasks.get_evaluation_task(direct_task_id)
            if direct_task["status"] in {"completed", "failed", "cancelled"}:
                break
            await asyncio.sleep(0.02)

        assert direct_task["status"] == "completed"
        direct_results = await evaluation_tasks.get_evaluation_results(direct_task_id, offset=0, limit=10)
        assert direct_results["results"][0]["attack_method"] == evaluation_tasks.DIRECT_PROMPT_METHOD
        assert direct_results["results"][0]["generation_mode"] == "direct_prompt"

    asyncio.run(runner())
