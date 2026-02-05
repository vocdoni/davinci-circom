// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 1207538411960013991844083342412640046413250858810501095761042988890780202208;
    uint256 constant alphay  = 9675955898914191974013133666244298119992476089554699620339008373987586546261;
    uint256 constant betax1  = 4157003346252115631322254767762448845214052437846750359775617986731542571067;
    uint256 constant betax2  = 14639968793155328841529454421046145291291637500427799434421975665770979001488;
    uint256 constant betay1  = 19902704217186432881115738547578414059775540763684396719457153870528611427804;
    uint256 constant betay2  = 1007737339277544051519394977537230950590887620379586413045251907782060891703;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant deltax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant deltay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant deltay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

    
    uint256 constant IC0x = 9549399197181245769704045649317637383493389779777730276983075975280833306736;
    uint256 constant IC0y = 16180455485114293555885993515597837001574076495437268234042031679938627373115;
    
    uint256 constant IC1x = 7260101062515561682741772975407031356096396408926440651573370010260809355234;
    uint256 constant IC1y = 1691326964570617742052632230593076034128491117637095702457894659297621914594;
    
    uint256 constant IC2x = 13655681635891509842283300191735727610692530900905143909813677951204220581668;
    uint256 constant IC2y = 6928647440745231436283591779347527546593131040351824357589943872994728034358;
    
    uint256 constant IC3x = 19226107354611586610011343122140095628025114512902038816565473063397772013237;
    uint256 constant IC3y = 17694227053029444739408927255582415431365462419112404960241176849241776724946;
    
    uint256 constant IC4x = 17630786509966265075373920471663670827511161789890631442110736579057094897388;
    uint256 constant IC4y = 10645218093531632913679709159981529112226107235495854322582944447560617578991;
    
    uint256 constant IC5x = 19708940280584697791226600808576657625164316556968266083061406546639328789684;
    uint256 constant IC5y = 1903757946051276166776859879143367407644336554088458184154702132516801510096;
    
    uint256 constant IC6x = 19677290805395344509997038039587486336732182535737485280307681462910762161833;
    uint256 constant IC6y = 10433055442432478022456482903385355586747000638880366340556740654987427663858;
    
    uint256 constant IC7x = 19431588060995898706744604553521118164007826901553213162926928692307694737300;
    uint256 constant IC7y = 2132036130497019223345481379111859590655245428514525919761424052366889523484;
    
    uint256 constant IC8x = 11022923104691337145842297814983185620132284224623454173652419266415133097949;
    uint256 constant IC8y = 20124104924794749589257705475014231958193908461663017113462842220367257397266;
    
    uint256 constant IC9x = 20113410839743767967068274389306452755475909854896039817014616598647504345059;
    uint256 constant IC9y = 15065360435282113131104167439867848224906721318557604634269038065717150520166;
    
    uint256 constant IC10x = 20682718105385767684661034991052066048793314125615228681944536788069145189698;
    uint256 constant IC10y = 13330515124983919908857152225617918151342314719327844569331126690288958795359;
    
    uint256 constant IC11x = 18379062197657003169080097880879729051745511449585164624755524062031494945071;
    uint256 constant IC11y = 4251316522199041287563738647879320523629640387113788753880115240245505728554;
    
    uint256 constant IC12x = 16130740559510169424618428049413431190702985932292482263718249932931040913696;
    uint256 constant IC12y = 5951102205082159630264243490073811644796248971414782250096773276581462851876;
    
    uint256 constant IC13x = 11126408609765573101497354726085028180377050431218759209777266291332819679190;
    uint256 constant IC13y = 20127857653056673965362329590487301116137480362159213531277540642583707137931;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[13] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
