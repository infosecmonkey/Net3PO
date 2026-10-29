// Typed access to projects (collections of tool results, stored locally by
// the Rust side under the OS app data dir).

import { invoke } from "@tauri-apps/api/core";
import { openTool } from "$lib/nav.svelte";
import { generatedNow } from "$lib/report/export";
import type { Report, ReportFormat } from "$lib/report/types";

export interface ProjectSummary {
  id: string;
  name: string;
  /** Unix seconds. */
  created: number;
  updated: number;
  items: number;
}

export interface ProjectItem {
  id: string;
  tool: string;
  title: string;
  note: string;
  added: number;
  addedLabel: string;
  sections: string[];
}

export interface ProjectView {
  id: string;
  name: string;
  notes: string;
  created: number;
  updated: number;
  items: ProjectItem[];
}

export interface ItemEdit {
  id: string;
  title: string;
  note: string;
}

export const listProjects = () => invoke<ProjectSummary[]>("project_list");

export const createProject = (name: string) => invoke<ProjectSummary>("project_create", { name });

export const getProject = (id: string) => invoke<ProjectView>("project_get", { id });

export const updateProject = (id: string, name: string, notes: string, items: ItemEdit[]) =>
  invoke<ProjectView>("project_update", { id, name, notes, items });

export const deleteProject = (id: string) => invoke<void>("project_delete", { id });

/** Add a tool's report to a project, stamped with the current time. */
export function addToProject(id: string, report: Report): Promise<ProjectSummary> {
  const label = generatedNow();
  return invoke<ProjectSummary>("project_add", {
    id,
    tool: report.tool ?? "",
    addedLabel: label,
    report: { ...report, generated: report.generated ?? label },
  });
}

export const exportProject = (id: string, format: ReportFormat, path: string) =>
  invoke<number>("project_export", { id, format, path, generated: generatedNow() });

/** A project the Projects panel should select when it next mounts. */
let pendingSelect: string | null = null;

/** Open the Projects tool with a project selected. */
export function openProject(id: string) {
  pendingSelect = id;
  openTool("projects");
}

/** Take the project to select, if any, clearing it. */
export function takePendingProject(): string | null {
  const id = pendingSelect;
  pendingSelect = null;
  return id;
}
