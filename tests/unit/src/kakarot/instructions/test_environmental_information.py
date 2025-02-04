import pytest
import pytest_asyncio
from starkware.starknet.testing.starknet import Starknet


@pytest_asyncio.fixture(scope="module")
async def environmental_information(starknet: Starknet):
    return await starknet.deploy(
        source="./tests/unit/src/kakarot/instructions/test_environmental_information.cairo",
        cairo_path=["src"],
        disable_hint_validation=True,
    )


@pytest.mark.asyncio
class TestEnvironmentalInformation:
    async def test_address(
        self,
        environmental_information,
    ):
        await environmental_information.test__exec_address__should_push_address_to_stack().call()

    async def test_extcodesize(
        self,
        environmental_information,
        account_registry,
    ):
        await environmental_information.test__exec_extcodesize__should_handle_address_with_no_code(
            account_registry_address=account_registry.contract_address
        ).call()

    async def test_extcodecopy(
        self,
        environmental_information,
        account_registry,
    ):
        await environmental_information.test__exec_extcodecopy__should_handle_address_with_no_code(
            account_registry_address=account_registry.contract_address
        ).call()
