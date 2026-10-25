@extends('admin.layout')
@section('title', 'Audit integrity')
@section('content')
<h1 class="title is-3">Audit trail integrity</h1>
<div class="notification {{ $integrity['valid'] ? 'is-success' : 'is-danger' }}">
	<strong>
		{{ ($integrity['valid'] ?? false) ? 'Hash chain verified' : 'Integrity verification failed' }}
	</strong>
	· {{ number_format($integrity['entries'] ?? 0) }} entries
	@if (!empty($integrity['error_sequence']))
	    · Error at sequence {{ $integrity['error_sequence'] }}
	@endif
</div>
<div class="box table-container">
	<table class="table is-fullwidth">
		<thead>
			<tr>
				<th>Sequence</th>
				<th>Time</th>
				<th>Actor ID</th>
				<th>Action</th>
				<th>Details</th>
			</tr>
		</thead>
		<tbody>
			@forelse ($entries as $entry)
				<tr>
					<td>{{ $entry->sequence_number }}</td>
					<td>{{ \Illuminate\Support\Carbon::parse($entry->occurred_at)->format('M j, Y g:i:s A') }}</td>
					<td>{{ $entry->actor_public_id ?? 'System' }}</td>
					<td>{{ $entry->action }}</td>
					<td>{{ \Illuminate\Support\Str::limit($entry->details ?? '', 180) }}</td>
				</tr>
			@empty
			<tr>
				<td colspan="5">No audit entries recorded.</td>
			</tr>
			@endforelse
		</tbody>
	</table>
</div>
{{ $entries->links() }}
@endsection
