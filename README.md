# EDI-CLI

CLI tool for working with EDI files.

This crate is still a work in progress.

Edifact implementation is based on the [edifact-types](https://crates.io/crates/edifact-types) crate.
X12 implementation is based on the [x12-types](https://crates.io/crates/x12-types) crate.

# Install

We currently only support install through cargo

```
cargo install edi-cli
```

# Usage

```
% ./edi 
Edi file processing

Usage: edi <COMMAND>

Commands:
  edi2json  Transforms an EDI into a Json document
  json2edi  Transforms an Json into a EDI document
  encoding  returns either 'X12' or 'EDIFACT' if encoding can be determined, otherwise 'UNKNOWN'.
  type      returns the X12 or EDIFACT message type
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help information
  -V, --version  Print version information
```

## get encoding
```
% ./edi encoding 004010_315.edi 
X12
```

## get type
```
% ./edi type 004010_315.edi 
004010/315
```

## edi2json
```
% ./edi edi2json 004010_315.edi 
{"isa":{"01":"00","02":"          ","03":"00","04":"          ","05":"ZZ","06":"SOURCE         ","07":"ZZ","08":"TARGET         ","09":"220524","10":"1120","11":"U","12":"00401","13":"000000001","14":"0","15":"P","16":">"},"functional_group":[{"gs":{"01":"QO","02":"SOURCE","03":"TARGET","04":"20220524","05":"1600","06":"1","07":"X","08":"004010"},"segments":[{"st":{"01":"315","02":"00001"},"b4":{"03":"VA","04":"20220901","05":"0807","07":"GMCU","08":"609413","09":"E","11":"LOCKBOURNE","12":"CI","13":"7"},"n9":[{"01":"BM","02":"21001ASK5V9U"},{"01":"BN","02":"1NAN910141"},{"01":"EQ","02":"GMCU6094137"}],"q2":{"01":"9330141","09":"202N","12":"L","13":"MARIM"},"loop_r4":[{"r4":{"01":"L","02":"UN","03":"USMEM","04":"BNSF MEMPHIS RAMP","05":"US","08":"US"}},{"r4":{"01":"E","02":"UN","03":"USDAL","04":"BNSF ALLIANCE RAMP","05":"US","08":"US"}}],"se":{"01":"9","02":"00001"}}],"ge":{"01":"1","02":"1"}}],"iea":{"01":"1","02":"000000001"}}
```

# Supported standards

`edi2json` and `json2edi` round-trip the X12 transaction sets listed below (the
X12 release version is taken from `GS-08`, the transaction set from `ST-01`).
EDIFACT documents are recognised by the `encoding` and `type` commands, but
conversion is not yet implemented.

## X12 003030

| Set | Description       |
| --- | ----------------- |
| 998 | Set Cancellation  |

## X12 004010

| Set | Description                                      |
| --- | ------------------------------------------------ |
| 204 | Motor Carrier Load Tender                        |
| 214 | Transportation Carrier Shipment Status Message   |
| 301 | Confirmation (Ocean)                             |
| 309 | U.S. Customs Manifest                            |
| 310 | Freight Receipt and Invoice (Ocean)              |
| 315 | Status Details (Ocean)                           |
| 322 | Terminal Operations and Intermodal Ramp Activity |
| 404 | Rail Carrier Shipment Information                |
| 810 | Invoice                                          |
| 856 | Ship Notice/Manifest                             |
| 940 | Warehouse Shipping Order                         |
| 945 | Warehouse Shipping Advice                        |
| 997 | Functional Acknowledgment                        |
| 998 | Set Cancellation                                 |

## X12 005010

| Set | Description                                              |
| --- | ------------------------------------------------------- |
| 148 | Report of Injury, Illness or Incident                   |
| 163 | Transportation Appointment Schedule Information         |
| 180 | Return Merchandise Authorization and Notification       |
| 204 | Motor Carrier Load Tender                               |
| 210 | Motor Carrier Freight Details and Invoice               |
| 211 | Motor Carrier Bill of Lading                            |
| 212 | Motor Carrier Delivery Trailer Manifest                 |
| 214 | Transportation Carrier Shipment Status Message          |
| 216 | Motor Carrier Shipment Pickup Notification              |
| 217 | Motor Carrier Loading and Route Guide                   |
| 270 | Eligibility, Coverage or Benefit Inquiry                |
| 271 | Eligibility, Coverage or Benefit Information            |
| 274 | Healthcare Provider Information                          |
| 275 | Patient Information                                     |
| 276 | Health Claim Status Request                             |
| 277 | Health Care Claim Status                                |
| 278 | Health Care Services Review Information                 |
| 300 | Reservation (Booking Request) (Ocean)                   |
| 301 | Confirmation (Ocean)                                    |
| 303 | Booking Cancellation (Ocean)                            |
| 304 | Shipping Instructions                                   |
| 309 | Customs Manifest                                        |
| 310 | Freight Receipt and Invoice (Ocean)                     |
| 315 | Status Details (Ocean)                                  |
| 350 | Customs Status Information                               |
| 353 | Customs Events Advisory Details                         |
| 404 | Rail Carrier Shipment Information                       |
| 417 | Rail Carrier Waybill Interchange                        |
| 425 | Rail Waybill Request                                    |
| 753 | Request for Routing Instructions                        |
| 754 | Routing Instructions                                    |
| 810 | Invoice                                                 |
| 811 | Consolidated Service Invoice/Statement                  |
| 812 | Credit/Debit Adjustment                                 |
| 816 | Organizational Relationships                            |
| 820 | Payment Order/Remittance Advice                         |
| 821 | Financial Information Reporting                         |
| 822 | Account Analysis                                        |
| 823 | Lockbox                                                 |
| 824 | Application Advice                                      |
| 830 | Planning Schedule with Release Capability               |
| 832 | Price/Sales Catalog                                     |
| 834 | Benefit Enrollment and Maintenance                      |
| 835 | Health Care Claim Payment/Advice                        |
| 837 | Health Care Claim                                       |
| 840 | Request for Quotation                                   |
| 843 | Response to Request for Quotation                       |
| 845 | Price Authorization Acknowledgment/Status               |
| 846 | Inventory Inquiry/Advice                                |
| 850 | Purchase Order                                          |
| 852 | Product Activity Data                                   |
| 855 | Purchase Order Acknowledgment                           |
| 856 | Ship Notice/Manifest                                    |
| 857 | Shipment and Billing Notice                             |
| 860 | Purchase Order Change Request - Buyer Initiated         |
| 861 | Receiving Advice/Acceptance Certificate                 |
| 862 | Shipping Schedule                                       |
| 864 | Text Message                                            |
| 865 | Purchase Order Change Acknowledgment/Request - Seller Initiated |
| 866 | Production Sequence                                     |
| 867 | Product Transfer and Resale Report                      |
| 869 | Order Status Inquiry                                    |
| 870 | Order Status Report                                     |
| 875 | Grocery Products Purchase Order                         |
| 880 | Grocery Products Invoice                                |
| 888 | Item Maintenance                                        |
| 889 | Promotion Announcement                                  |
| 940 | Warehouse Shipping Order                                |
| 943 | Warehouse Stock Transfer Shipment Advice                |
| 944 | Warehouse Stock Transfer Receipt Advice                 |
| 945 | Warehouse Shipping Advice                               |
| 990 | Response to a Load Tender                               |
| 997 | Functional Acknowledgment                               |
| 999 | Implementation Acknowledgment                           |

## X12 005030

| Set | Description                       |
| --- | --------------------------------- |
| 404 | Rail Carrier Shipment Information |
