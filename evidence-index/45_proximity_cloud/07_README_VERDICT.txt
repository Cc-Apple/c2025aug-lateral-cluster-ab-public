45 Proximity vs Cloud Separation Review
============================================================

Final verdict:
  PROXIMITY_CLOUD_SEPARATION_SUPPORTED_NOT_SERVER_SIDE_PROOF

Meaning:
  C2025AUG / 2025-08-04 について、物理接触・同一Wi-Fiで説明しやすい端末と、cloud/trust graph側の説明が必要になる端末を分離した。

High cloud/trust separation:
  EXT_NO_CONTACT_A, EXT_REMOTE_GEO_C

Cloud/trust review:
  EXT_UNCERTAIN_B

Physical/local explanation still possible:
  EXT_CONTACT_D, EXT_CONTACT_E_12PROMAX, EXT_CONTACT_E_6SPLUS, USER_ORIGIN_MINI1, USER_DEVICE_12G, USER_DEVICE_11PRO, USER_BRIDGE_15G, USER_DEVICE_MINI2

Claim boundary:
  - Apple server-side trust graph の直接証明ではない。
  - Family Sharing / trusted device 追加の直接証明ではない。
  - BSSID/RSSI同一や物理接近を断定しない。
  - proximity artifact と trust/backup overlap を分離整理するscript。

Next:
  46 Evidence Preservation / Suppression Model
