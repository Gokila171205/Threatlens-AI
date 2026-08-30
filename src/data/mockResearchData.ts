export interface DatasetSample {
  id: string;
  fileName: string;
  sha256: string;
  family: string;
  type: string;
  size: number;
  entropy: number;
  addedDate: string;
  yaraRule: string;
  downloadable: boolean;
}

export const MOCK_RESEARCH_DATASET: DatasetSample[] = [
  {
    id: 'res-ds-01',
    fileName: 'lockbit_v3_gen5_sample.bin',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    family: 'LockBit 3.0',
    type: 'PE32+ Executable x86-64',
    size: 1048576,
    entropy: 7.94,
    addedDate: '2026-08-30T08:00:00Z',
    yaraRule: 'PE_HighEntropy_PackedSection',
    downloadable: true,
  },
  {
    id: 'res-ds-02',
    fileName: 'cobalt_strike_beacon_4.9.dll',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    family: 'Cobalt Strike',
    type: 'PE32+ DLL x86-64',
    size: 458752,
    entropy: 6.82,
    addedDate: '2026-08-29T14:20:00Z',
    yaraRule: 'SUSP_PowerShell_C2_Gen',
    downloadable: true,
  },
  {
    id: 'res-ds-03',
    fileName: 'emotet_epoch5_macro.docm',
    sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    family: 'Emotet Trojan',
    type: 'Office Word Macro',
    size: 342112,
    entropy: 6.42,
    addedDate: '2026-08-28T11:15:00Z',
    yaraRule: 'DOCM_Macro_Encoded_PS1',
    downloadable: true,
  },
  {
    id: 'res-ds-04',
    fileName: 'agenttesla_v2.8_stealer.exe',
    sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    family: 'AgentTesla',
    type: 'PE32 .NET Assembly',
    size: 786432,
    entropy: 7.10,
    addedDate: '2026-08-27T09:40:00Z',
    yaraRule: 'NET_Assembly_Stealer_Gen',
    downloadable: true,
  },
];
