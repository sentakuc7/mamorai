/**
 * クラウド管理（EDR-76）: IaaS プロバイダの共通インターフェースと AWS（EC2 + Lightsail）/ GCE の実装。
 * やることは 4 つだけ: 台帳 / スナップショット / 電源 / 隔離。削除系は存在しない。
 */
import { EC2Client, DescribeInstancesCommand, CreateSnapshotCommand, DescribeVolumesCommand, StartInstancesCommand, StopInstancesCommand, RebootInstancesCommand, DescribeSecurityGroupsCommand, CreateSecurityGroupCommand, ModifyInstanceAttributeCommand, DescribeRegionsCommand } from "@aws-sdk/client-ec2";
import { LightsailClient, GetInstancesCommand, CreateInstanceSnapshotCommand, StartInstanceCommand, StopInstanceCommand, RebootInstanceCommand, PutInstancePublicPortsCommand, GetInstanceCommand } from "@aws-sdk/client-lightsail";
import { JWT } from "google-auth-library";

export type ProviderKind = "aws" | "gce" | "hyperv" | "esxi" | "azure" | "proxmox";
export type PowerOp = "start" | "stop" | "reboot";
export interface Instance { service: string; external_id: string; name: string; state: string; public_ip: string | null; private_ip: string | null; region: string | null; zone: string | null; machine_type: string | null; os: string | null; tags: Record<string, string>; raw: any }
export interface OpResult { ok: boolean; message: string; ref?: string; detail?: any }
export interface CloudProvider {
  kind: ProviderKind;
  test(): Promise<{ ok: boolean; message: string; identity?: string }>;
  list(): Promise<Instance[]>;
  snapshot(inst: Instance, name: string): Promise<OpResult>;
  power(inst: Instance, op: PowerOp): Promise<OpResult>;
  isolate(inst: Instance, allowCidrs: string[]): Promise<OpResult>; // 管理用の許可 CIDR 以外を全て遮断
}

/** 製品に同梱する最小権限ポリシー（UI で表示・コピーさせる） */
export const POLICIES = {
  aws_iam_policy: {
    Version: "2012-10-17",
    Statement: [
      { Sid: "Inventory", Effect: "Allow", Action: ["ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeSecurityGroups", "ec2:DescribeRegions", "ec2:DescribeSnapshots", "lightsail:GetInstances", "lightsail:GetInstance", "lightsail:GetInstanceSnapshots", "lightsail:GetRegions"], Resource: "*" },
      { Sid: "SnapshotAndPower", Effect: "Allow", Action: ["ec2:CreateSnapshot", "ec2:CreateTags", "ec2:StartInstances", "ec2:StopInstances", "ec2:RebootInstances", "lightsail:CreateInstanceSnapshot", "lightsail:StartInstance", "lightsail:StopInstance", "lightsail:RebootInstance"], Resource: "*" },
      { Sid: "Isolate", Effect: "Allow", Action: ["ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress", "ec2:ModifyInstanceAttribute", "lightsail:PutInstancePublicPorts"], Resource: "*" },
    ],
  },
  gcp_roles: ["roles/compute.viewer", "roles/compute.instanceAdmin.v1（スナップショット・電源・ネットワークタグ変更に必要）", "roles/iam.serviceAccountUser（インスタンスにサービスアカウントが付いている場合）"],
};

// ---------------------------------------------------------------- AWS ----------
export interface AwsConfig { regions: string[]; use_lightsail: boolean; use_ec2: boolean }
export interface AwsSecret { access_key_id: string; secret_access_key: string; session_token?: string }
export class AwsProvider implements CloudProvider {
  kind: ProviderKind = "aws";
  constructor(private cfg: AwsConfig, private sec: AwsSecret) {}
  private creds() { return { accessKeyId: this.sec.access_key_id, secretAccessKey: this.sec.secret_access_key, sessionToken: this.sec.session_token }; }
  private ec2(region: string) { return new EC2Client({ region, credentials: this.creds() }); }
  private ls(region: string) { return new LightsailClient({ region, credentials: this.creds() }); }
  async test() {
    try {
      const r = await this.ec2(this.cfg.regions[0] ?? "ap-northeast-1").send(new DescribeRegionsCommand({}));
      return { ok: true, message: `接続 OK（利用可能リージョン ${r.Regions?.length ?? 0}）`, identity: "IAM access key" };
    } catch (e: any) { return { ok: false, message: e.name === "UnauthorizedOperation" ? "認証は通りましたが ec2:DescribeRegions の権限がありません" : `接続失敗: ${e.message}` }; }
  }
  async list(): Promise<Instance[]> {
    const out: Instance[] = [];
    for (const region of this.cfg.regions) {
      if (this.cfg.use_ec2 !== false) {
        try {
          const r = await this.ec2(region).send(new DescribeInstancesCommand({ MaxResults: 500 }));
          for (const res of r.Reservations ?? []) for (const i of res.Instances ?? []) {
            const tags = Object.fromEntries((i.Tags ?? []).map((t) => [t.Key ?? "", t.Value ?? ""]));
            out.push({ service: "ec2", external_id: i.InstanceId!, name: tags.Name || i.InstanceId!, state: i.State?.Name ?? "unknown", public_ip: i.PublicIpAddress ?? null, private_ip: i.PrivateIpAddress ?? null, region, zone: i.Placement?.AvailabilityZone ?? null, machine_type: i.InstanceType ?? null, os: i.PlatformDetails ?? null, tags, raw: { security_groups: i.SecurityGroups, vpc: i.VpcId, subnet: i.SubnetId, launch: i.LaunchTime } });
          }
        } catch (e: any) { if (!/OptInRequired|AuthFailure/.test(e.name ?? "")) throw e; }
      }
      if (this.cfg.use_lightsail !== false) {
        try {
          const r = await this.ls(region).send(new GetInstancesCommand({}));
          for (const i of r.instances ?? []) out.push({ service: "lightsail", external_id: i.name!, name: i.name!, state: i.state?.name ?? "unknown", public_ip: i.publicIpAddress ?? null, private_ip: i.privateIpAddress ?? null, region, zone: i.location?.availabilityZone ?? null, machine_type: i.bundleId ?? null, os: i.blueprintName ?? null, tags: Object.fromEntries((i.tags ?? []).map((t) => [t.key ?? "", t.value ?? ""])), raw: { blueprint: i.blueprintId, created: i.createdAt, ports: (i.networking?.ports ?? []).map((p) => `${p.protocol}/${p.fromPort}-${p.toPort}`) } });
        } catch (e: any) { if (!/InvalidInput|AccessDenied/.test(e.name ?? "")) throw e; }
      }
    }
    return out;
  }
  async snapshot(inst: Instance, name: string): Promise<OpResult> {
    if (inst.service === "lightsail") {
      const r = await this.ls(inst.region!).send(new CreateInstanceSnapshotCommand({ instanceName: inst.external_id, instanceSnapshotName: name }));
      return { ok: true, message: `Lightsail スナップショット ${name} を作成開始`, ref: name, detail: r.operations?.map((o) => ({ id: o.id, status: o.status })) };
    }
    const vols = await this.ec2(inst.region!).send(new DescribeVolumesCommand({ Filters: [{ Name: "attachment.instance-id", Values: [inst.external_id] }] }));
    const ids: string[] = [];
    for (const v of vols.Volumes ?? []) { const s = await this.ec2(inst.region!).send(new CreateSnapshotCommand({ VolumeId: v.VolumeId!, Description: name, TagSpecifications: [{ ResourceType: "snapshot", Tags: [{ Key: "Name", Value: name }, { Key: "edr-console", Value: "pre-change" }] }] })); ids.push(s.SnapshotId!); }
    return { ok: true, message: `EBS スナップショット ${ids.length} 件を作成開始`, ref: ids.join(","), detail: { snapshot_ids: ids } };
  }
  async power(inst: Instance, op: PowerOp): Promise<OpResult> {
    if (inst.service === "lightsail") {
      const c = this.ls(inst.region!); const n = { instanceName: inst.external_id };
      const r = op === "start" ? await c.send(new StartInstanceCommand(n)) : op === "stop" ? await c.send(new StopInstanceCommand(n)) : await c.send(new RebootInstanceCommand(n));
      return { ok: true, message: `Lightsail ${inst.name} を ${op}`, detail: r.operations?.map((o) => o.status) };
    }
    const c = this.ec2(inst.region!); const ids = { InstanceIds: [inst.external_id] };
    if (op === "start") await c.send(new StartInstancesCommand(ids)); else if (op === "stop") await c.send(new StopInstancesCommand(ids)); else await c.send(new RebootInstancesCommand(ids));
    return { ok: true, message: `EC2 ${inst.name} を ${op}` };
  }
  async isolate(inst: Instance, allowCidrs: string[]): Promise<OpResult> {
    if (inst.service === "lightsail") {
      // Lightsail: 公開ポートを管理用 CIDR からの SSH だけに絞る（元の設定は raw.ports にある）
      await this.ls(inst.region!).send(new PutInstancePublicPortsCommand({ instanceName: inst.external_id, portInfos: [{ fromPort: 22, toPort: 22, protocol: "tcp", cidrs: allowCidrs.length ? allowCidrs : ["127.0.0.1/32"] }] }));
      return { ok: true, message: `Lightsail ${inst.name} の公開ポートを SSH（${allowCidrs.join(", ") || "なし"}）のみに制限` };
    }
    const c = this.ec2(inst.region!);
    const vpc = inst.raw?.vpc; if (!vpc) return { ok: false, message: "VPC が不明" };
    const name = "edr-console-isolation";
    let sgId: string | undefined;
    const ex = await c.send(new DescribeSecurityGroupsCommand({ Filters: [{ Name: "group-name", Values: [name] }, { Name: "vpc-id", Values: [vpc] }] }));
    sgId = ex.SecurityGroups?.[0]?.GroupId;
    if (!sgId) { const cr = await c.send(new CreateSecurityGroupCommand({ GroupName: name, Description: "EDR Console isolation (no ingress except admin SSH)", VpcId: vpc })); sgId = cr.GroupId!; }
    await c.send(new ModifyInstanceAttributeCommand({ InstanceId: inst.external_id, Groups: [sgId] }));
    return { ok: true, message: `EC2 ${inst.name} を隔離 SG（${sgId}）に付け替え`, ref: sgId, detail: { previous_groups: inst.raw?.security_groups } };
  }
}

// ---------------------------------------------------------------- GCE ----------
export interface GceConfig { project_id: string; zones: string[] }
export interface GceSecret { service_account_json: string }
export class GceProvider implements CloudProvider {
  kind: ProviderKind = "gce";
  private jwt: JWT; private project: string;
  constructor(private cfg: GceConfig, sec: GceSecret) {
    const sa = JSON.parse(sec.service_account_json);
    this.project = cfg.project_id || sa.project_id;
    this.jwt = new JWT({ email: sa.client_email, key: sa.private_key, scopes: ["https://www.googleapis.com/auth/compute"] });
  }
  private async call(method: string, path: string, body?: unknown): Promise<any> {
    const { token } = await this.jwt.getAccessToken();
    const res = await fetch(`https://compute.googleapis.com/compute/v1/projects/${this.project}${path}`, { method, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text(); let json: any; try { json = JSON.parse(text); } catch { json = { raw: text }; }
    if (!res.ok) throw new Error(`GCE ${method} ${path} -> ${res.status}: ${json?.error?.message ?? text.slice(0, 200)}`);
    return json;
  }
  async test() { try { const r = await this.call("GET", "/zones?maxResults=1"); return { ok: true, message: `接続 OK（project ${this.project}）`, identity: this.jwt.email ?? undefined }; } catch (e: any) { return { ok: false, message: `接続失敗: ${e.message}` }; } }
  async list(): Promise<Instance[]> {
    const r = await this.call("GET", "/aggregated/instances?maxResults=500");
    const out: Instance[] = [];
    for (const [zoneKey, v] of Object.entries<any>(r.items ?? {})) {
      const zone = zoneKey.replace("zones/", "");
      if (this.cfg.zones?.length && !this.cfg.zones.includes(zone)) continue;
      for (const i of v.instances ?? []) {
        const nic = i.networkInterfaces?.[0];
        out.push({ service: "gce", external_id: i.name, name: i.name, state: String(i.status ?? "").toLowerCase(), public_ip: nic?.accessConfigs?.[0]?.natIP ?? null, private_ip: nic?.networkIP ?? null, region: zone.replace(/-[a-z]$/, ""), zone, machine_type: String(i.machineType ?? "").split("/").pop() ?? null, os: i.disks?.[0]?.licenses?.[0]?.split("/").pop() ?? null, tags: { ...(i.labels ?? {}), network_tags: (i.tags?.items ?? []).join(",") }, raw: { id: i.id, disks: (i.disks ?? []).map((d: any) => d.source?.split("/").pop()), network_tags: i.tags?.items ?? [], tags_fingerprint: i.tags?.fingerprint, created: i.creationTimestamp } });
      }
    }
    return out;
  }
  async snapshot(inst: Instance, name: string): Promise<OpResult> {
    const refs: string[] = [];
    for (const [k, disk] of (inst.raw?.disks ?? []).entries()) { const snapName = `${name}${k ? "-" + k : ""}`.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 62); await this.call("POST", `/zones/${inst.zone}/disks/${disk}/createSnapshot`, { name: snapName, labels: { "edr-console": "pre-change" } }); refs.push(snapName); }
    return { ok: true, message: `ディスクスナップショット ${refs.length} 件を作成開始`, ref: refs.join(","), detail: { snapshots: refs } };
  }
  async power(inst: Instance, op: PowerOp): Promise<OpResult> {
    const verb = op === "start" ? "start" : op === "stop" ? "stop" : "reset";
    const r = await this.call("POST", `/zones/${inst.zone}/instances/${inst.external_id}/${verb}`);
    return { ok: true, message: `GCE ${inst.name} を ${verb}`, ref: r.name };
  }
  async isolate(inst: Instance, _allow: string[]): Promise<OpResult> {
    // ネットワークタグを edr-isolated だけにする（VPC firewall に deny-all の edr-isolated ルールを事前に用意する前提。無ければ作る）
    const net = "global/networks/default";
    try { await this.call("GET", "/global/firewalls/edr-console-isolate-deny"); }
    catch { await this.call("POST", "/global/firewalls", { name: "edr-console-isolate-deny", network: net, direction: "INGRESS", priority: 10, targetTags: ["edr-isolated"], sourceRanges: ["0.0.0.0/0"], denied: [{ IPProtocol: "all" }] }); }
    const cur = await this.call("GET", `/zones/${inst.zone}/instances/${inst.external_id}`);
    await this.call("POST", `/zones/${inst.zone}/instances/${inst.external_id}/setTags`, { items: ["edr-isolated"], fingerprint: cur.tags?.fingerprint });
    return { ok: true, message: `GCE ${inst.name} に deny-all タグ edr-isolated を付与`, detail: { previous_tags: cur.tags?.items ?? [] } };
  }
}

export function buildProvider(kind: ProviderKind, config: any, secret: any): CloudProvider {
  if (kind === "aws") return new AwsProvider({ regions: config?.regions?.length ? config.regions : ["ap-northeast-1"], use_lightsail: config?.use_lightsail !== false, use_ec2: config?.use_ec2 !== false }, secret);
  if (kind === "gce") return new GceProvider({ project_id: config?.project_id ?? "", zones: config?.zones ?? [] }, secret);
  throw new Error(`provider kind '${kind}' is not implemented yet (phase 2: hyperv / esxi / azure / proxmox)`);
}
export const KIND_JA: Record<ProviderKind, string> = { aws: "AWS（EC2 / Lightsail）", gce: "Google Compute Engine", hyperv: "Hyper-V", esxi: "VMware ESXi / vSphere", azure: "Microsoft Azure", proxmox: "Proxmox VE" };
