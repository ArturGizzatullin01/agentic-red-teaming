"""src/memnotsafe/core/campaign_construction.py — ARC-2: конструирование судьи и
атакующего клиента кампании (вынесено из core/campaign.py при расщеплении).
Миксин к Campaign. Судья строится через ленивый импорт judge.runtime (как было);
атакующий клиент/бюджет/дефолтный конфиг — через шов core/campaign_backend,
поэтому ядро не импортирует memnotsafe.generation. Поведение прежнее — тела
перенесены дословно, изменены только строки границы generation в
_ensure_attacker.
"""

from __future__ import annotations

from memnotsafe.core.campaign_backend import campaign_backend


class CampaignConstructionMixin:
    def _build_judge(self):
        spec = self.scenario.judge
        if not spec.enabled:
            return None
        from memnotsafe.judge.runtime import LLMJudge

        return LLMJudge(
            spec,
            repetitions=self.scenario.repetitions,
            artifacts_dir=self.output_dir / "judge",
        )

    def _ensure_attacker(self):
        """Ленивое создание атакующего клиента и бюджета — только когда онлайн-
        уровень реально включён. Без `--online` этот путь не исполняется (SC-003)."""
        if self._attacker_client is not None:
            return
        backend = campaign_backend()

        config = self.attacker_config or backend.default_attacker_config()
        self.attacker_config = config
        self._attacker_client = backend.build_attacker_client(config)
        self._budget = backend.new_call_budget(config.budget)


    async def aclose_attacker(self) -> None:
        if self._attacker_client is not None:
            await self._attacker_client.aclose()

