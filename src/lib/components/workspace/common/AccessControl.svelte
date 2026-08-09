<script lang="ts">
	import { getContext, onMount } from 'svelte';

	const i18n = getContext('i18n');

	import { getGroups } from '$lib/apis/groups';
	import { getUserById, searchUsers } from '$lib/apis/users';
	import { config } from '$lib/stores';
	import Tooltip from '$lib/components/common/Tooltip.svelte';
	import Plus from '$lib/components/icons/Plus.svelte';
	import UserCircleSolid from '$lib/components/icons/UserCircleSolid.svelte';
	import XMark from '$lib/components/icons/XMark.svelte';
	import Badge from '$lib/components/common/Badge.svelte';

	export let onChange: Function = () => {};

	export let accessRoles = ['read'];
	export let accessControl = {};

	export let share = true;
	export let sharePublic = true;

	// Which model this resource is, as the server names it. The server says
	// which of those can only be shared with people named one by one, so this
	// only offers audiences that will actually be accepted.
	export let resourceType: string | null = null;

	$: namedOnly = (($config?.sharing?.named_recipients_only ?? []) as string[]).includes(
		resourceType ?? ''
	);

	// Public needs both the permission and a resource whose readers are not
	// enumerated as key holders.
	$: canBePublic = sharePublic && !namedOnly;

	let selectedGroupId = '';
	let groups = [];

	let userQuery = '';
	let userResults = [];
	let knownUsers: Record<string, { id: string; name: string; email: string }> = {};

	$: if (!canBePublic && accessControl === null) {
		initPublicAccess();
	}

	const initPublicAccess = () => {
		if (!canBePublic && accessControl === null) {
			accessControl = {
				read: {
					group_ids: [],
					user_ids: []
				},
				write: {
					group_ids: [],
					user_ids: []
				}
			};
			onChange(accessControl);
		}
	};

	const rememberUser = async (userId: string) => {
		if (knownUsers[userId]) {
			return;
		}
		const user = await getUserById(localStorage.token, userId).catch(() => null);
		if (user) {
			knownUsers = { ...knownUsers, [userId]: user };
		}
	};

	const findUsers = async () => {
		if (userQuery.trim() === '') {
			userResults = [];
			return;
		}
		const res = await searchUsers(localStorage.token, userQuery).catch(() => null);
		userResults = res?.users ?? [];
	};

	const addUser = async (user) => {
		accessControl.read.user_ids = [...(accessControl?.read?.user_ids ?? []), user.id];
		knownUsers = { ...knownUsers, [user.id]: user };

		userQuery = '';
		userResults = [];
		onChange(accessControl);
	};

	const removeUser = (userId: string) => {
		accessControl.read.user_ids = (accessControl?.read?.user_ids ?? []).filter(
			(id) => id !== userId
		);
		accessControl.write.user_ids = (accessControl?.write?.user_ids ?? []).filter(
			(id) => id !== userId
		);
		onChange(accessControl);
	};

	onMount(async () => {
		groups = await getGroups(localStorage.token, true);

		if (accessControl === null) {
			initPublicAccess();
		} else {
			accessControl = {
				read: {
					group_ids: accessControl?.read?.group_ids ?? [],
					user_ids: accessControl?.read?.user_ids ?? []
				},
				write: {
					group_ids: accessControl?.write?.group_ids ?? [],
					user_ids: accessControl?.write?.user_ids ?? []
				}
			};

			for (const userId of [
				...(accessControl?.read?.user_ids ?? []),
				...(accessControl?.write?.user_ids ?? [])
			]) {
				rememberUser(userId);
			}
		}
	});
</script>

<div class=" rounded-lg flex flex-col gap-2">
	<div class="">
		<div class=" text-xs font-medium mb-2.5 text-gray-500">{$i18n.t('Visibility')}</div>

		<div class="flex gap-2.5 items-center mb-1">
			<div>
				<div class=" p-2 bg-black/5 dark:bg-white/5 rounded-full">
					{#if accessControl !== null}
						<svg
							xmlns="http://www.w3.org/2000/svg"
							fill="none"
							viewBox="0 0 24 24"
							stroke-width="1.5"
							stroke="currentColor"
							class="w-5 h-5"
						>
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"
							/>
						</svg>
					{:else}
						<svg
							xmlns="http://www.w3.org/2000/svg"
							fill="none"
							viewBox="0 0 24 24"
							stroke-width="1.5"
							stroke="currentColor"
							class="w-5 h-5"
						>
							<path
								stroke-linecap="round"
								stroke-linejoin="round"
								d="M6.115 5.19l.319 1.913A6 6 0 008.11 10.36L9.75 12l-.387.775c-.217.433-.132.956.21 1.298l1.348 1.348c.21.21.329.497.329.795v1.089c0 .426.24.815.622 1.006l.153.076c.433.217.956.132 1.298-.21l.723-.723a8.7 8.7 0 002.288-4.042 1.087 1.087 0 00-.358-1.099l-1.33-1.108c-.251-.21-.582-.299-.905-.245l-1.17.195a1.125 1.125 0 01-.98-.314l-.295-.295a1.125 1.125 0 010-1.591l.13-.132a1.125 1.125 0 011.3-.21l.603.302a.809.809 0 001.086-1.086L14.25 7.5l1.256-.837a4.5 4.5 0 001.528-1.732l.146-.292M6.115 5.19A9 9 0 1017.18 4.64M6.115 5.19A8.965 8.965 0 0112 3c1.929 0 3.716.607 5.18 1.64"
							/>
						</svg>
					{/if}
				</div>
			</div>

			<div>
				<select
					id="models"
					class="dark:bg-gray-900 outline-hidden bg-transparent text-sm font-medium block w-fit pr-10 max-w-full placeholder-gray-400"
					value={accessControl !== null ? 'private' : 'public'}
					on:change={(e) => {
						if (e.target.value === 'public') {
							accessControl = null;
						} else {
							accessControl = {
								read: {
									group_ids: [],
									user_ids: []
								},
								write: {
									group_ids: [],
									user_ids: []
								}
							};
						}
						onChange(accessControl);
					}}
				>
					<option class=" text-gray-700" value="private" selected>{$i18n.t('Private')}</option>
					{#if share && canBePublic}
						<option class=" text-gray-700" value="public" selected>{$i18n.t('Public')}</option>
					{/if}
				</select>

				<div class=" text-xs text-gray-400 font-medium">
					{#if namedOnly}
						{$i18n.t('Encrypted content can only be shared with people you name')}
					{:else if accessControl !== null}
						{$i18n.t('Only select users and groups with permission can access')}
					{:else}
						{$i18n.t('Accessible to all users')}
					{/if}
				</div>
			</div>
		</div>
	</div>

	{#if share && namedOnly && accessControl !== null}
		{@const memberIds = accessControl?.read?.user_ids ?? []}
		<div>
			<div class="flex justify-between mb-2.5">
				<div class="text-xs font-medium text-gray-500">
					{$i18n.t('People')}
				</div>
			</div>

			{#if memberIds.length > 0}
				<div class="flex flex-col gap-1.5 mb-2 px-0.5 mx-0.5">
					{#each memberIds as userId}
						<div class="flex items-center gap-3 justify-between text-sm w-full transition">
							<div class="flex items-center gap-1.5 w-full">
								<div>
									{knownUsers[userId]?.name ?? userId}
									<span class="text-xs text-gray-500">{knownUsers[userId]?.email ?? ''}</span>
								</div>
							</div>

							<div class="w-full flex justify-end items-center gap-0.5">
								<button
									class=""
									type="button"
									on:click={() => {
										if (accessRoles.includes('write')) {
											if ((accessControl?.write?.user_ids ?? []).includes(userId)) {
												accessControl.write.user_ids = (
													accessControl?.write?.user_ids ?? []
												).filter((id) => id !== userId);
											} else {
												accessControl.write.user_ids = [
													...(accessControl?.write?.user_ids ?? []),
													userId
												];
											}
											onChange(accessControl);
										}
									}}
								>
									{#if (accessControl?.write?.user_ids ?? []).includes(userId)}
										<Badge type={'success'} content={$i18n.t('Write')} />
									{:else}
										<Badge type={'info'} content={$i18n.t('Read')} />
									{/if}
								</button>

								<button
									class=" rounded-full p-1 hover:bg-gray-100 dark:hover:bg-gray-850 transition"
									type="button"
									on:click={() => removeUser(userId)}
								>
									<XMark />
								</button>
							</div>
						</div>
					{/each}
				</div>
			{/if}

			<div class="mb-1 px-0.5">
				<input
					class="w-full text-sm bg-transparent outline-hidden dark:placeholder-gray-500"
					placeholder={$i18n.t('Search for a person to share with')}
					bind:value={userQuery}
					on:input={findUsers}
				/>

				{#if userResults.length > 0}
					<div class="flex flex-col gap-1 mt-2">
						{#each userResults.filter((user) => !memberIds.includes(user.id)) as user}
							<button
								class="flex items-center gap-1.5 text-sm text-left px-1 py-1 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-850 transition"
								type="button"
								on:click={() => addUser(user)}
							>
								<Plus className="size-3" />
								<span>{user.name}</span>
								<span class="text-xs text-gray-500">{user.email}</span>
							</button>
						{/each}
					</div>
				{/if}
			</div>
		</div>
	{/if}

	{#if share && !namedOnly}
		{#if accessControl !== null}
			{@const accessGroups = groups.filter((group) =>
				(accessControl?.read?.group_ids ?? []).includes(group.id)
			)}
			<div>
				<div class="">
					<div class="flex justify-between mb-2.5">
						<div class="text-xs font-medium text-gray-500">
							{$i18n.t('Groups')}
						</div>
					</div>

					{#if accessGroups.length > 0}
						<div class="flex flex-col gap-1.5 mb-2 px-0.5 mx-0.5">
							{#each accessGroups as group}
								<div class="flex items-center gap-3 justify-between text-sm w-full transition">
									<div class="flex items-center gap-1.5 w-full">
										<div>
											{group.name} <span class="text-xs text-gray-500">{group?.member_count}</span>
										</div>
									</div>

									<div class="w-full flex justify-end items-center gap-0.5">
										<button
											class=""
											type="button"
											on:click={() => {
												if (accessRoles.includes('write')) {
													if ((accessControl?.write?.group_ids ?? []).includes(group.id)) {
														accessControl.write.group_ids = (
															accessControl?.write?.group_ids ?? []
														).filter((group_id) => group_id !== group.id);
													} else {
														accessControl.write.group_ids = [
															...(accessControl?.write?.group_ids ?? []),
															group.id
														];
													}
													onChange(accessControl);
												}
											}}
										>
											{#if (accessControl?.write?.group_ids ?? []).includes(group.id)}
												<Badge type={'success'} content={$i18n.t('Write')} />
											{:else}
												<Badge type={'info'} content={$i18n.t('Read')} />
											{/if}
										</button>

										<button
											class=" rounded-full p-1 hover:bg-gray-100 dark:hover:bg-gray-850 transition"
											type="button"
											on:click={() => {
												accessControl.read.group_ids = (
													accessControl?.read?.group_ids ?? []
												).filter((id) => id !== group.id);
												accessControl.write.group_ids = (
													accessControl?.write?.group_ids ?? []
												).filter((id) => id !== group.id);
												onChange(accessControl);
											}}
										>
											<XMark />
										</button>
									</div>
								</div>
							{/each}
						</div>
					{/if}

					<!-- <div class="flex items-center justify-center">
						<div class="text-gray-500 text-xs text-center py-2 px-10">
							{$i18n.t('No groups with access, add a group to grant access')}
						</div>
					</div> -->

					<div class="mb-1">
						<div class="flex w-full">
							<div class="flex flex-1 items-center">
								<div class="w-full px-0.5">
									<select
										class=" outline-hidden bg-transparent text-sm block w-full pr-10 max-w-full
									{selectedGroupId ? '' : 'text-gray-500'}
									dark:placeholder-gray-500"
										bind:value={selectedGroupId}
										on:change={() => {
											if (selectedGroupId !== '') {
												accessControl.read.group_ids = [
													...(accessControl?.read?.group_ids ?? []),
													selectedGroupId
												];

												selectedGroupId = '';
												onChange(accessControl);
											}
										}}
									>
										<option class=" text-gray-700" value="" disabled selected
											>{$i18n.t('Select a group')}</option
										>
										{#each groups.filter((group) => !(accessControl?.read?.group_ids ?? []).includes(group.id)) as group}
											<option class=" text-gray-700" value={group.id}>{group.name}</option>
										{/each}
									</select>
								</div>
							</div>
						</div>
					</div>
				</div>
			</div>
		{/if}
	{/if}
</div>
