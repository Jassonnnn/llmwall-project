from guardrails import Guard, OnFailAction
from hub import CompetitorCheck

guard = Guard().use(
    CompetitorCheck(["Apple", "Microsoft", "Google"], on_fail=OnFailAction.FIX),
)

guard.validate(
    """An apple a day keeps a doctor away.
    This is good advice for keeping your health."""
)  # Both the guardrails pass

try:
    print(guard.validate(
        """Shut the hell up! Apple just released a new iPhone.""")
    )  # Both the guardrails fail)
except Exception as e:
    print("111",e)