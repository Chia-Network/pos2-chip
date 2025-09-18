#include "common/Utils.hpp"
#include "pos/ProofCore.hpp"
#include "pos/ProofValidator.hpp"

/*
./verify 28 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF 3abd1c6a594df48e0448e07b7f08109ea7e8fd120a5130fb10c5234473b577eafd8ce34804dc12f3c4964e690cda3672e9be37565a102755b2586679a5e144f724c154e5dd08745bd3af4a00b5d0f083762870b8936c05f12a63346c328d6c7ce6cf9c1c0472012c4d16d04c90e79e5f352db513ae9b70526da5638436339fa16beb446d335cd8fe0291f37d022d53409636c404f3d9429a2d2aaf67f79fa7bc2613ee45cc28eddd41d02feb8cbce4b3b5dd311b557c2570ed04af34deac72c98e89a8d897f41dc5b3ab835db7e3d16fa056dbb63f05e509467138fca05e4d417db317450c03dadc13d09ba83cbc1af980f18a3fe41cc3f3beb40f7edfddc0dcde50919bbf4d07c9cc3bbf60f6513b0cffc99f39652dd52bd28e44449f89759369d3eed11f9ed8882e4febf041a423d573cdbd683df8aefd598ddcf7d557591db7cc2fdf7f806bf4ae735b42801e80c885b64a6fc6533d0594fba9a133754858e3d45d891eb0f299db9bcc31d4d5976249b7afe5c5065d336bf92f846bf40e192f917b81c0218eaa723c83e9bc7bef340298d6db9c612ebf93c927c69d8d8d6317853d50ce956750ec89d16da127db713b776bcbaf7aa42ffee9c02f79f800e3bae9070792ec68588696b9be79c46e7185319baa339aebd83ac072698908d68a4f4684559557c39ce5c6aa903f4d2ff1a28c61ed7bfab162f56844e76bd851a9e2787f719f4c9d6f1fc4920d3b902e81c46306beacb18a0b20899ff901e29632688fe1cdb0237f893303782a4106ac6862efd6f1f208c3076091b08d6a5efc1a92c569362f17942e76435506aa93473c24393936dac38dfc0dab26032b6b908a68d054ba70702b2ee6028c4db4fe31b8a0679a530d7b2d4dae23aa5b536e86095b386fc0c0a36f81ac45225714046437854eb6804160c55925abed05e082cdae0fbe41ada93dd40058241fa8d6e3291fe0721ba497f28f7ed6ebafce0af0cdfceea94456c51e734658ea1420d6d0c41aa5c3ee1861f3f6e3418e2a31fb05115f535bfea388bafb333404ce34026deda44e4dd4e17b6162da5406db5535ebd477072e0e30037a2a14a10f3099b82de0fed26d55523a70bf5cd3ff12403408f71dc5eac81c8a6165d8b2067db4d91a8f7216a48c97c59d451692e8cda31af5f5851556e1f4ca55e91367dd6b02d12f2e46487a93a5edfc8920f0a20f51bb6ccf401a8918cdadd7d297355348a1570971b2252a3a63040da7032c7bb1a781ac365a449fe7cf4bd20fb2d77675b47fbf690a6f0c34e3d0d8f86011a20e6d89f3687980fa5238bc9d68576fd35295c42de04f1d6c370f0666eb5c8c9ab405fe8a3c28a28ad6a07cb73999beba04e762771b90756a56fa043ba755c80428621f62f0912dfe1ce3ab03077d327a618f831efcb77e5742fd9ca314984a9eeb997ac54fbbd16049a74ee47c171deadce09674d6e1dab6245b589e0893e1a4aef65cf353d11b62f44c27fb8a9a1f7e791f7091fd890c3cf3232c8970c243281af8de98306ec76be12ada38609b3672d5e6ecc63b85af55a1f96b07a41f6547e15bfccae1f8273a7d4ddefe82f280438b1f2e480b0523e07fcc5705cb244f00aed6b746e8010730878cba7bcbc8023527968ea263343d71336b81126d7c4ce2edd21c8cec2ca538f01d0b573f896dd06e1f3d757420b88ea1b72d0cf5ec213cc21900c0af172ffb103fe970ef152802decfa3739d2c60a8981f4b21f711e17eb30699293b958e17b915e1d8de078c15f48bb43296eb36e2b85e3a2614867364cb358c15f06486c510cdec5dab22ed25d140d238ecbee1e0fceb0744a609e5da465affc1dbffde247e0202a2f218597dc072f114c0a468b945878a4008a5d15bdd992887b765a4cabe8c9298c58e182bf6f69967cc92ddbf43bd5442977dc713c9135595873a174d3453d0ca2efa48adadd9e3cc84683360550c1a970a135ac22378a4c904971e39cbe7345cc0d0d6142eed408ad6bc2c15623af40bf1c0191eca082e9a4e5c0505e5baed8350e2019e7c6dc54a82a3a4cabe8c9298c58e182bf6f69967cc92ddbf43bd5442977dc713c9135595873a174d3453d0ca2efa48adadd9e3cc84683360550c1a970a139dd6e587d0661640b8bf9f8296559ce0f11aa23d5ffb15e7c07757b6e4105885c29b566f5a718f410f1d071447162e9f8ea8849016c4b5587a811002740d5553183a1ae9ffe983b82742bc617bba1bfd12774d98ff30da84863261ab778887a8aee7ef434ada0e29c789b0b193340dff473b8deaf4a2cce50250b301340b19710e3fe8bcaee74f4f56b845f79cdbd20e2aac93a35d1cecb9cb48e840f9aa8232134e287217ae5a1742d1d53149d09f3853a3a9503697527331fc99bfc84ab2e9817703cb2c61d50587e22cfbdcc2e38d1b7b8a846e770cecacacf8e66c96ed54ca9871e83ad61989f60bad1d11ec1a6118f4a3deeea5f0c869e5c8cd47de1ea354ced01e85ff1084856d15fbf84ad704bf278b5af7680edd 1717171717171717171717171717171717171717171717171717171717171717
*/

int main(int argc, char *argv[])
{
    std::cout << "Verify: given a k-size, hex proof, and 32 byte hex challenge, verify the proof." << std::endl;
    if (argc < 4 || argc > 5)
    {
        std::cerr << "Usage: " << argv[0] << " [k] [hexPlotId] [hexProof] [hexChallenge]\n";
        return 1;
    }
    int k = std::stoi(argv[1]);
    if (k != 28 && k != 30 && k != 32)
    {
        std::cerr << "Error: k-size must be 28, 30, or 32." << std::endl;
        return 1;
    }
    std::string plot_id_hex = argv[2];
    if (plot_id_hex.length() != 64)
    {
        std::cerr << "Error: plot ID must be 64 hex characters." << std::endl;
        return 1;
    }
    std::string proof_hex = argv[3];
    std::string challenge_hex = argv[4];
    if (challenge_hex.length() != 64)
    {
        std::cerr << "Error: challenge must be 64 hex characters." << std::endl;
        return 1;
    }

    std::cout << "Verifying proof for k=" << k << ", plot ID=" << plot_id_hex << ", challenge=" << challenge_hex << ", proof=" << proof_hex << std::endl;
    std::array<uint8_t, 32> plot_id = Utils::hexToBytes(plot_id_hex);
    std::array<uint8_t, 32> challenge = Utils::hexToBytes(challenge_hex);
    ProofParams params(plot_id.data(), k); // sub_k is 20 for now
    ProofValidator proof_validator(params);
    ProofCore proof_core(params);

    std::vector<uint32_t> proof = Utils::hexToProof(k, proof_hex);

    // get all sub-proofs, which are collections of 32 x-values
    if (proof_validator.validate_full_proof(proof, challenge))
    {
        std::cout << "Proof is valid." << std::endl;
    }
    else
    {
        std::cerr << "Proof validation failed." << std::endl;
        return 1;
    }

    
}